package main

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	//"strings"
	"time"

	"golang.org/x/crypto/scrypt"
)

// ejemplo de tipo para un usuario
type user struct {
	Name string            // nombre de usuario
	Hash []byte            // hash de la contraseña
	Salt []byte            // sal para la contraseña
	Data map[string]string // datos adicionales del usuario
	Ok  bool   // true -> correcto, false -> error
	Msg string // mensaje adicional
	ConfigurationFile []byte
}

// mapa con todos los usuarios
// (se podría codificar en JSON y escribir/leer de disco para persistencia)
var gUsers map[string]user

const nombreFicheroUsuario = "users.json"
const MaximumBackupsSaved = 6

//maxPolicy numero de políticas máxima
const maxPolicy = 50

//MaximumAllowedRequestSize en MB
const MaximumAllowedRequestSize = 50 * 1000000

type PeriodicityType string

const (
	//Daily diaria
	Daily PeriodicityType = "Diaria"
	DailySmartDelete PeriodicityType = "Diaria con borrado"
	//Weekly semanal
	Weekly PeriodicityType = "Semanal"
	WeeklySmartDelete PeriodicityType = "Semanal con borrado"
	//Monthly mensual
	Monthly PeriodicityType = "Mensual"
	MonthlySmartDelete PeriodicityType = "Mensual con borrado"
	//Sync sincronización automática
	Sync PeriodicityType = "Sincronizado"
	EveryXminutes PeriodicityType = "Cada x minutos"
	DailyInHour PeriodicityType = "Diaria a las hh-mm"
)

// función para cifrar (con AES en este caso), adjunta el IV al principio
func encrypt(data, key []byte) (out []byte) {
	out = make([]byte, len(data)+16)    // reservamos espacio para el IV al principio
	rand.Read(out[:16])                 // generamos el IV
	blk, err := aes.NewCipher(key)      // cifrador en bloque (AES), usa key
	chk(err)                            // comprobamos el error
	ctr := cipher.NewCTR(blk, out[:16]) // cifrador en flujo: modo CTR, usa IV
	ctr.XORKeyStream(out[16:], data)    // ciframos los datos
	return
}

// función para descifrar (con AES en este caso)
func decrypt(data, key []byte) (out []byte) {
	out = make([]byte, len(data)-16)     // la salida no va a tener el IV
	blk, err := aes.NewCipher(key)       // cifrador en bloque (AES), usa key
	chk(err)                             // comprobamos el error
	ctr := cipher.NewCTR(blk, data[:16]) // cifrador en flujo: modo CTR, usa IV
	ctr.XORKeyStream(out, data[16:])     // desciframos (doble cifrado) los datos
	return
}

// función para codificar de []bytes a string (Base64)
func encode64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data) // sólo utiliza caracteres "imprimibles"
}

// función para decodificar de string a []bytes (Base64)
func decode64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s) // recupera el formato original
	chk(err)                                     // comprobamos el error
	return b                                     // devolvemos los datos originales
}

// función para comprimir
func compress(data []byte) []byte {
	var b bytes.Buffer      // b contendrá los datos comprimidos (tamaño variable)
	w := zlib.NewWriter(&b) // escritor que comprime sobre b
	w.Write(data)           // escribimos los datos
	w.Close()               // cerramos el escritor (buffering)
	return b.Bytes()        // devolvemos los datos comprimidos
}

// función para descomprimir
func decompress(data []byte) []byte {
	var b bytes.Buffer // b contendrá los datos descomprimidos

	r, err := zlib.NewReader(bytes.NewReader(data)) // lector descomprime al leer

	chk(err)         // comprobamos el error
	io.Copy(&b, r)   // copiamos del descompresor (r) al buffer (b)
	r.Close()        // cerramos el lector (buffering)
	return b.Bytes() // devolvemos los datos descomprimidos
}

// respuesta del servidor
type resp struct {
	Ok  bool   // true -> correcto, false -> error
	Msg string // mensaje adicional
}

type respListBackups struct {
	Ok      bool
	Backups []string
}

type respUserFolder struct {
	Ok        bool
	Path      string
	NumFiles  int
	Files     []byte
	FileNames string
}

// función para escribir una respuesta del servidor
func response(w io.Writer, ok bool, msg string) {
	r := resp{Ok: ok, Msg: msg}    // formateamos respuesta
	rJSON, err := json.Marshal(&r) // codificamos en JSON
	chk(err)                       // comprobamos error
	w.Write(rJSON)                 // escribimos el JSON resultante
}

// función para comprobar errores (ahorra escritura)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

func chkStatus(state bool) {
	if !state {
		panic(1)
	}
}

type usuario struct {
	Name string // nombre de usuario
	//Hash []byte            // hash de la contraseña
	//Salt []byte            // sal para la contraseña
	//Data map[string]string // datos adicionales del usuario
}

func checkIfRegistered(userToRegister user, w http.ResponseWriter) {
	_, ok := gUsers[userToRegister.Name] // ¿existe ya el usuario?

	if ok {
		response(w, false, "Usuario ya registrado")
	} else {
		gUsers[userToRegister.Name] = userToRegister
		keyClient := sha512.Sum512([]byte(os.Args[1]))

		content, _ := json.MarshalIndent(gUsers, "", " ")
		encryptedContent := encrypt(content, keyClient[:32])

		file, err := os.OpenFile(nombreFicheroUsuario, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
		chk(err)
		defer file.Close()
		
		fmt.Println("Escribiendo en " + nombreFicheroUsuario)
		_, err = file.Write(encryptedContent)
		chk(err)
		
		response(w, true, "Usuario registrado")
	}
}
func checkCorrectPath(name string) string {
	namePath := ""
	for i := 0; i < len(name); i++ {
		if name[i] != '\\' && name[i] != '/' && name[i] != ':' && name[i] != '*' && name[i] != '?' && name[i] != '"' && name[i] != '<' && name[i] != '>' && name[i] != '|' {
			namePath = namePath + string(name[i])
		}
	}
	return namePath
}

func checkLogin(w http.ResponseWriter, userName string, pass string, sendResponse ...bool) (*user, bool) {
	u, ok := gUsers[userName]
	if !ok {
		r := user{Ok: false, Msg: "Usuario inexistente"}
		rJSON, err := json.Marshal(&r)
		chk(err)
		w.Write(rJSON)

		return &user{}, false
	}
	password := decode64(pass)                               // obtenemos la contraseña
	hash, _ := scrypt.Key(password, u.Salt, 16384, 8, 1, 32) // scrypt(contraseña)
	if bytes.Compare(u.Hash, hash) != 0 {                    // comparamos
		r := user{Ok: false, Msg: "Credenciales inválidas"}
		rJSON, err := json.Marshal(&r)
		chk(err)
		w.Write(rJSON)
		return &user{}, false
	}

	r := gUsers[userName]

	//Mando la respuesta al server solo lo indico
	if len(sendResponse) != 0{
		if sendResponse[0] {
			r.Ok = true
			r.Msg = "Bienvenido " + userName
			ConfigurationFile := getConfigurationFile(u.Name)
			if(ConfigurationFile != nil){
				r.ConfigurationFile = ConfigurationFile
			}
			rJSON, err := json.Marshal(&r)
			chk(err)
			w.Write(rJSON)
		}
	}

	return &u, true
}

func readUsers() {
	jsonFile, err := os.Open("users.json")
	defer jsonFile.Close()
	
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("users.json abierto correctamente")

	byteValue, _ := ioutil.ReadAll(jsonFile)
	keyClient := sha512.Sum512([]byte(os.Args[1]))

	json.Unmarshal(decrypt(byteValue, keyClient[:32]), &gUsers)
}
func getConfigurationFile(name string) []byte {

	configurationFolderPath := filepath.Join(".", "configuration")
	_, err := os.Stat(configurationFolderPath)
	if os.IsNotExist(err) {
		err := os.MkdirAll(configurationFolderPath, 0755)
		chk(err)
	}

	jsonFile, err := os.Open(filepath.Join(configurationFolderPath, name + ".json"))
	// if we os.Open returns an error then handle it
	if err != nil {
		fmt.Println(err)
		return nil
	}
	fmt.Println("Enviando al cliente ", filepath.Join(configurationFolderPath, name + ".json"))
	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	//keyClient := sha512.Sum512([]byte(user.pass)
	//json.Unmarshal(decrypt(byteValue, keyClient[:32]), &user)
	return byteValue
}
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// gestiona el modo servidor
func server() {
	gUsers = make(map[string]user) // inicializamos mapa de usuarios
	readUsers()
	//for k, v := range gUsers {
	//	if fileExists(checkCorrectPath(k) + ".json") {
	//		readPolicy(checkCorrectPath(k), &v)
	//	}
	//}
	//fmt.Printf(gUsers["bc46@alu.ua.es"].policy[1].PathFolder)
	// Para generar certificados autofirmados con openssl usar:
	//    openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/C=ES/ST=Alicante/L=Alicante/O=UA/OU=Org/CN=www.ua.com"
	//Creo así al servidor para tener más control, por ejemplo ahora puedo cambiar el tamaño máximos de las cabeceras...
	mux := http.NewServeMux()
	mux.HandleFunc("/", handler)

	server := &http.Server{
		Addr:    ":10443",
		Handler: mux,
	}

	fmt.Println("Escuchando por el puerto 10443..")
	chk(server.ListenAndServeTLS("cert.pem", "key.pem"))

}
func handler(w http.ResponseWriter, req *http.Request) {

	body, err := ioutil.ReadAll(req.Body)
	chk(err)

	p, err := url.ParseQuery(string(body))
	chk(err)

	var params map[string]string
	params = make(map[string]string)

	for k, v := range p {
		params[k] = v[0]
	}

	command := params["cmd"]
	userName := params["user"]
	pass := params["pass"]

	contentLength, err := strconv.Atoi(req.Header.Get("Content-Length"))
	if contentLength >= MaximumAllowedRequestSize {
		command = "tooBig"
	}

	//w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	fmt.Println("Se intenta conectar el usuario: " + userName) // Muestro el usuario que se ha conectado
	switch command {                                       // comprobamos comando desde el cliente

	case "tooBig":
		response(w, false, "Se ha excedido el límite de capacidad")
	case "register": // ** registro
		user := user{}
		user.Name = userName                // nombre
		user.Salt = make([]byte, 16)        // sal (16 bytes == 128 bits)
		rand.Read(user.Salt)                // la sal es aleatoria
		user.Data = make(map[string]string) // reservamos mapa de datos de usuario
		password := decode64(pass) // contraseña (keyLogin)
		// "hasheamos" la contraseña con scrypt
		user.Hash, _ = scrypt.Key(password, user.Salt, 16384, 8, 1, 32)

		checkIfRegistered(user, w)

	case "login": // ** login
		checkLogin(w, userName, pass, true)
	case "send", "sendFolder", "automatedBackup":
		_, state := checkLogin(w, userName, pass, false)
		chkStatus(state)

		removedOld := false
		var deletes string

		periodicity := params["periodicity"]
		
		userFolderPath := filepath.Join(".", checkCorrectPath(gUsers[userName].Name), periodicity)
		_, err := os.Stat(userFolderPath)

		if os.IsNotExist(err) {
			err := os.MkdirAll(userFolderPath, 0755)
			chk(err)
		}
		
		//empieza el borrado
		files, err := ioutil.ReadDir(userFolderPath)
		chk(err)
		var nToDelete int
		if len(files) >= MaximumBackupsSaved && (PeriodicityType(periodicity) == DailySmartDelete || PeriodicityType(periodicity) == WeeklySmartDelete || PeriodicityType(periodicity) == MonthlySmartDelete){
			nToDelete = len(files) - MaximumBackupsSaved + 1
			deletes = strconv.Itoa(nToDelete)
		}else{
			nToDelete = -1
		}

		var pathsToRemove []string
		if(nToDelete != -1){
			for _,file := range files{
				pathsToRemove = append(pathsToRemove, file.Name())
				nToDelete--
				if(nToDelete == 0){
					break
				}
			}
		}

		for _, name := range pathsToRemove{
			err := os.RemoveAll(filepath.Join(userFolderPath, name))
			removedOld = true
			fmt.Println("Eliminando la copia antigua... ", name)
			chk(err)
		}

		dt := time.Now()
		folderPath := filepath.Join(userFolderPath, dt.Format("01-02-2006 15-04-05"))

		fmt.Println("Ruta de la carpeta:", folderPath)
		os.Mkdir(folderPath, 0777)

		var fileNames string
		fileNamesBin := []byte(params["fileNames"])
		err = json.Unmarshal(fileNamesBin, &fileNames)
		chk(err)

		var encryptedFiles []byte
		encryptedFilesBin := []byte(params["encryptedFiles"])
		err = json.Unmarshal(encryptedFilesBin, &encryptedFiles)
		chk(err)

		//	for _, name := range fileNames {
		//Si no existe crea el fichero, si existe, sobreescribe su contenido
		filePath := filepath.Join(folderPath, fileNames)
		file, err := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
		chk(err)
		defer file.Close()

		fmt.Println("Escribiendo en " + filePath)
		_, err = file.Write(encryptedFiles)
		chk(err)
		//}

		if(! removedOld){
			response(w, true, "Operación realizada con éxito")
		}else{
			response(w, true, deletes)
		}

	case "getListPeriodicity", "getListBackups":
		_, state := checkLogin(w, userName, pass, false)
		chkStatus(state)

		var files []os.FileInfo

		if command == "getListBackups" {
			periodicity := params["periodicity"]
			files, err = ioutil.ReadDir(filepath.Join(".", checkCorrectPath(gUsers[userName].Name), periodicity))
			chk(err)
		} else {
			files, err = ioutil.ReadDir(filepath.Join(".", checkCorrectPath(gUsers[userName].Name)))
			chk(err)
		}

		options := make([]string, len(files))
		for i, file := range files {
			options[i] = file.Name()
		}

		r := respListBackups{Ok: true, Backups: options}
		rJSON, err := json.Marshal(&r)
		chk(err)
		w.Write(rJSON)

	case "getBackup":
		_, state := checkLogin(w, userName, pass, false)
		chkStatus(state)

		path := params["path"]
		backupName := params["backupName"]
		periodicity := params["periodicity"]

		filesPath := filepath.Join(".", checkCorrectPath(gUsers[userName].Name), periodicity, backupName)
		files, err := ioutil.ReadDir(filesPath)
		chk(err)

		nF := len(files)
		//fN := make([]string, nF)
		var fN string
		f := make([]byte, nF)
		for _, file := range files {
			fN = file.Name()
			f, err = ioutil.ReadFile(filepath.Join(filesPath, fN))
			chk(err)
		}

		r := respUserFolder{
			Ok:        true,
			Path:      path,
			NumFiles:  nF,
			Files:     f,
			FileNames: fN,
		}

		rJSON, err := json.Marshal(&r)
		chk(err)
		w.Write(rJSON)
	
	case "updateConfigFile":
		_, state := checkLogin(w, userName, pass, false)
		chkStatus(state)
		policies := params["policies"]

		configurationFolderPath := filepath.Join(".", "configuration")
		_, err := os.Stat(configurationFolderPath)
		if os.IsNotExist(err) {
			err := os.MkdirAll(configurationFolderPath, 0755)
			chk(err)
		}

		file, err := os.OpenFile(filepath.Join(configurationFolderPath, checkCorrectPath(gUsers[userName].Name) + ".json"), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
		chk(err)
		defer file.Close()
		_, err = file.Write([]byte(policies))
		chk(err)

		response(w, true, "Actualizado fichero de configuración")
	
	default:
		response(w, false, "Comando inválido")
	}

}
func main() {
	if len(os.Args) == 2 {
		server()
	} else {
		fmt.Println("Error se necesita un parametro de contraseña")
	}
}
