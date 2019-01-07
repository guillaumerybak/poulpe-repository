package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"strings"
	"sync"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/handlers"
)

var repositoriesCachePath = "cache"
var repositoriesDataPath = "packages"

const keycloakClientID = ""
const keycloakClientSecret = ""
const keycloakOpenIDTokenUrl = ""

func createRepo(repositoryName string) bool {
	log.Println("[] Reposition creation asked for", repositoriesDataPath, repositoryName)

	repositoryFolder := path.Join(repositoriesDataPath, repositoryName)

	log.Println("[] Creating repository folder")

	err := os.MkdirAll(repositoryFolder, 0700)

	if err != nil {
		log.Fatal("[] Error creating repository folder:", err)
		return false
	}

	return true
}

func updateRepositoryMetadata(repositoryPath string, wg *sync.WaitGroup) bool {
	defer (*wg).Done()

	log.Println("[] Updating metadata for repository", repositoryPath)

	cmd := exec.Command("createrepo", "--update", "--cachedir", repositoriesCachePath, repositoryPath)
	start := time.Now()
	output, err := cmd.Output()
	t := time.Now()

	if err != nil {
		log.Fatal(err, output)
		return false
	}

	log.Printf("[] Metadata for repo %s updated succesfully in %dms", repositoryPath, t.Sub(start).Nanoseconds()/int64(time.Millisecond))
	return true
}

func updateRepositoriesMetadata(repositoryName string) {
	var repositories, err = ioutil.ReadDir(repositoriesDataPath)

	if err != nil {
		log.Fatal(err)
	}

	var wg sync.WaitGroup

	if repositoryName == "" {
		log.Println("[] Updating metadata for all repositories")

		wg.Add(len(repositories))

		for i := 0; i < len(repositories); i++ {
			go updateRepositoryMetadata(path.Join(repositoriesDataPath, repositories[i].Name()), &wg)
		}

	} else {
		wg.Add(1)
		updateRepositoryMetadata(path.Join(repositoriesDataPath, repositoryName), &wg)
	}

	wg.Wait()
}

type tokenResponseBody struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	NotBeforePolicy  int    `json:"not-before-policy"`
	SessionState     string `json:"session_state"`
	Scope            string `json:"scope"`
}

func getUserToken(password string, username string) (string, error) {
	var bytes []byte
	var resp, err = http.PostForm(keycloakOpenIDTokenUrl,
		url.Values{
			"grant_type":    {"password"},
			"client_id":     {keycloakClientID},
			"client_secret": {keycloakClientSecret},
			"username":      {username},
			"password":      {password},
		})

	if err != nil {
		return string(bytes), err
	}

	defer resp.Body.Close()

	bytes, err = ioutil.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return string(bytes), errors.New("Error getting token, status:" + resp.Status)
	}

	var body tokenResponseBody
	err = json.Unmarshal(bytes, &body)
	if err != nil {
		return string(bytes), err
	}

	return body.AccessToken, err
}

func httpPackagesHandler(w http.ResponseWriter, r *http.Request) {
	user, pass, ok := r.BasicAuth()

	if user != "" && pass != "" && ok {
		accessToken, err := getUserToken(pass, user)

		if err != nil {
			log.Fatal("[] Authentication Error:", err)
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized.", http.StatusUnauthorized)
			return
		}

		log.Println("[] Authentication succeeded for", user, ":", r.URL)
		log.Println("[] Getting user informations for", user)

		// Parse takes the token string and a function for looking up the key. The latter is especially
		// useful if you use multiple keys for your application.  The standard is to use 'kid' in the
		// head of the token to identify which key to use, but the parsed token (head and claims) is provided
		// to the callback, providing flexibility.
		token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
			// Don't forget to validate the alg is what you expect:
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}

			// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
			return []byte(keycloakClientSecret), nil
		})

		claims, _ := token.Claims.(jwt.MapClaims)

		resourceAccess := claims["resource_access"]
		if resourceAccess == nil {
			log.Println("[] Authentication Error: missing resource_access")
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized.", http.StatusUnauthorized)
			return
		}

		pulpProd := resourceAccess.(map[string]interface{})["pulp-prod"]
		if pulpProd == nil {
			log.Println("[] Authentication Error: missing pulp-prod claim")
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized.", http.StatusUnauthorized)
			return
		}

		roles := pulpProd.(map[string]interface{})["roles"]
		if roles == nil {
			log.Println("[] Authentication Error: missing roles")
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized.", http.StatusUnauthorized)
			return
		}

		// check roles
		// currentURL := strings.Replace(r.URL.Path, "/packages", "", 1)
		for i := 0; i < len(roles.([]interface{})); i++ {
			role := fmt.Sprint(roles.([]interface{})[i])

			if role == "repos" {
				http.StripPrefix("/packages/", http.FileServer(http.Dir(repositoriesDataPath))).ServeHTTP(w, r)
				return
			}
		}

	}

	w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
	http.Error(w, "Unauthorized.", http.StatusUnauthorized)
	return
}

func httpPackageHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("[] PackageHandler: handling", r.Method, "on", r.URL)

	if r.Method == "POST" {
		r.ParseMultipartForm(1024)

		repository := r.FormValue("repository")
		if repository == "" {
			w.WriteHeader(404)
			return
		}

		log.Println("[] PackageHandler: package upload requested on repository", repository)
		repositoryPath := path.Join(repositoriesDataPath, repository)

		_, err := os.Stat(repositoryPath)
		if os.IsNotExist(err) {
			log.Printf("[] PackageHandler: repository '%s' does not exist", repository)
			w.WriteHeader(404)
			return
		}
		if err != nil {
			log.Printf("[] PackageHandler: repository '%s' is not currently available: %s", repository, err)
			w.WriteHeader(500)
			return
		}
		log.Printf("[] PackageHandler: repository exists, handling package")

		file, handler, err := r.FormFile("package")
		if err != nil {
			log.Println(err)
			return
		}
		defer file.Close()

		contentType := handler.Header.Get("Content-Type")
		if contentType != "application/x-redhat-package-manager" && contentType != "application/x-rpm" {
			log.Printf("[] PackageHandler: unhandled file type Content-Type, got %s", handler.Header.Get("Content-Type"))
			return
		}

		fmt.Fprintf(w, "%v", handler.Header)

		packagePath := path.Join(repositoryPath, handler.Filename)
		log.Printf("[] PackageHandler: downloading package %s -> %s", handler.Filename, packagePath)
		f, err := os.OpenFile(packagePath, os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			log.Println("[] PackageHandler: failed to open file for download:", err)
			return
		}
		defer f.Close()

		io.Copy(f, file)

		f.Close()

		updateRepositoriesMetadata(repository)
	} else {
		w.WriteHeader(404)
	}
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

	if (*r).Method == "OPTIONS" {
		return
	}

	http.FileServer(http.Dir("static")).ServeHTTP(w, r)
}

func getNextParam(currentPosition *int) string {
	if *currentPosition+1 >= len(os.Args) {
		return ""
	}
	if strings.HasPrefix(os.Args[*currentPosition+1], "--") {
		return ""
	}

	*currentPosition++

	return os.Args[*currentPosition]
}

func main() {
	var command string
	var repositoryName string
	var updateRepoAfterCreate = false

	for i := 0; i < len(os.Args); i++ {
		arg := os.Args[i]

		if i == 1 {
			command = os.Args[i]
		} else if arg == "--reponame" {
			repositoryName = getNextParam(&i)
		} else if arg == "--repospath" {
			repositoriesDataPath = getNextParam(&i)
		} else if arg == "--cachepath" {
			repositoriesCachePath = getNextParam(&i)
		} else if arg == "--updateaftercreate" {
			updateRepoAfterCreate = true
		}
	}

	flag.Parse()

	switch command {
	case "create-repo":
		{
			if repositoryName == "" || repositoriesDataPath == "" {
				return
			}
			if createRepo(repositoryName) && updateRepoAfterCreate {
				updateRepositoriesMetadata(repositoryName)
			}
		}
	case "update-metadata":
		{
			if repositoriesDataPath == "" {
				return
			}
			updateRepositoriesMetadata(repositoryName)
		}
	case "serve":
		{
			if repositoriesDataPath == "" {
				return
			}
			http.HandleFunc("/", handleRoot)
			http.HandleFunc("/packages/", httpPackagesHandler)
			http.HandleFunc("/api/package", httpPackageHandler)
			log.Fatal(http.ListenAndServe(":8000", handlers.LoggingHandler(os.Stdout, http.DefaultServeMux)))
		}
	}

	return
}
