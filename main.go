package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"github.com/zserge/lorca"
)

//variables globales
var uiGeneral lorca.UI
var usuarioGlobal *user
var keyData []byte

//PeriodicityCheckDuration Cada cuanto compruebo si hay que hacer un backup (en segundos)
const PeriodicityCheckDuration = 5 * time.Second
const maxPolicy = 50

//cada bind debe ser bloqueado hasta ser llamado, es por eso que necesitamos una estructura con mutex
type redirection struct {
	sync.Mutex
	ui lorca.UI
}

type responseListBackups struct {
	Ok      bool
	Backups []string
}
type configBackups struct {
	Ok      bool
	Backups map[string]string
}
type userFolder struct {
	sync.Mutex
	Ok        bool
	Path      string
	Files     []byte
	FileNames string
}

// PeriodicityType periocidad
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

//BackupType nombre backup
type BackupType string

const (
	//Complete completa
	Complete BackupType = "completa"
)

type policyType struct {
	PathFolder  string
	Periodicity PeriodicityType
	BackupType  BackupType
	LastBackup  time.Time
	NextBackup  time.Time
}

type user struct {
	sync.Mutex
	userName     string
	password     string
	folder       *userFolder
	puntualFiles *filesArray
	Policies     []policyType
	PoliciesOptionalValues map[int]string
}

type userServ struct {
	Name string            // nombre de usuario
	Hash []byte            // hash de la contraseña
	Salt []byte            // sal para la contraseña
	Data map[string]string // datos adicionales del usuario
	Ok  bool   // true -> correcto, false -> error
	Msg string // mensaje adicional
	ConfigurationFile []byte
}

type response struct {
	Ok  bool
	Msg string
}

type filesArray struct {
	sync.Mutex
	Files     []byte
	FileNames string
	dataFiles [][]byte
}

// función para comprobar errores (ahorra escritura)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

// función para cifrar (con AES en este caso), adjunta el IV al principio
func encrypt(data, key []byte) (out []byte) {
	out = make([]byte, len(data)+16) // reservamos espacio para el IV al principio
	/*El IV (initialization vector) es un número aleatorio que se añade al cuerpo del mensaje para prevenir la repetición
	y evitar así ataques tipo "dictionary attack",usamos 16 bytes porque es el tamaño del bloque de AES */
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

func storeBodyRequest(requestBody io.Reader, target interface{}) {
	body, err := ioutil.ReadAll(requestBody)
	chk(err)
	err = json.Unmarshal(body, &target)
	chk(err)
}

func directorios(path string, tw *tar.Writer) {
	dir, err := os.Open(path)
	chk(err)
	defer dir.Close()
	fis, err := dir.Readdir(0)
	chk(err)
	for _, fi := range fis {
		curPath := path + "/" + fi.Name()
		if fi.IsDir() {
			directorios(curPath, tw)
		} else {
			addFileTar(tw, curPath, fi)
		}
	}
}

func addFileTar(tw *tar.Writer, path string, fi os.FileInfo) {
	file, err := os.Open(path)
	chk(err)
	defer file.Close()
	// Get FileInfo about our file providing file size, mode, etc.
	info, err := file.Stat()
	chk(err)
	// Create a tar Header from the FileInfo data
	header, err := tar.FileInfoHeader(info, info.Name())
	chk(err)
	//header.Name = path
	rel, err := filepath.Rel(usuarioGlobal.folder.Path, path)
	header.Name = rel

	// Write file header to the tar archive
	err = tw.WriteHeader(header)
	chk(err)
	// Copy file content to tar archive
	_, err = io.Copy(tw, file)
	chk(err)
}
func empaqueTarFicheros(paths [][]byte, fileNames []string) string {
	dt := time.Now()
	folderPath := dt.Format("01-02-2006 15-04-05")
	folderPath = folderPath + ".tar.gz"
	// set up the output file
	file, err := os.Create(folderPath)
	chk(err)
	defer file.Close()
	// set up the gzip writer
	gw := gzip.NewWriter(file)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

	for i, data := range paths {
		hdr := &tar.Header{
			Name: fileNames[i],
			Mode: 0600,
			Size: int64(len(data)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			chk(err)
		}
		if _, err := tw.Write([]byte(data)); err != nil {
			chk(err)
		}
	}
	return folderPath
}
func empaqueTarCarpeta(path string) string {
	dt := time.Now()
	folderPath := dt.Format("01-02-2006 15-04-05")
	folderPath = folderPath + ".tar.gz"
	// set up the output file
	file, err := os.Create(folderPath)
	chk(err)
	defer file.Close()
	// set up the gzip writer
	gw := gzip.NewWriter(file)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

	directorios(path, tw)

	return folderPath
}

func untartar(tarName string, xpath string) (err error) {

	tarFile, err := os.Open(filepath.Join(xpath, tarName))
	chk(err)
	defer tarFile.Close()

	absPath, err := filepath.Abs(xpath)

	tr := tar.NewReader(tarFile)
	if strings.HasSuffix(tarName, ".gz") {
		gz, err := gzip.NewReader(tarFile)
		if err != nil {
			return err
		}
		defer gz.Close()
		tr = tar.NewReader(gz)
	}
  
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		// determine proper file path info
		finfo := hdr.FileInfo()
		fileName := hdr.Name
		
		fdir := filepath.Dir(fileName)
		bfile := filepath.Base(fileName)
		absFileName := filepath.Join(absPath, bfile)
		
		if(fdir != "."){
			fileName = fdir
			absFileName = filepath.Join(absPath, fdir, bfile)
		}

		// if a dir, create it, then go to next segment
		if finfo.Mode().IsDir() || fdir != "." {
			if err := os.MkdirAll(filepath.Join(xpath, fdir), 0755); err != nil {
				return err
			}
		}

		// create new file with original file mode
		file, err := os.OpenFile(
			absFileName, 
			os.O_RDWR|os.O_CREATE|os.O_TRUNC, 
			finfo.Mode().Perm(),
		)
		if err != nil {
			return err
		}

		n, cpErr := io.Copy(file, tr)
		if closeErr := file.Close(); closeErr != nil {
			return err
		}
		if cpErr != nil {
			return cpErr
		}
		if n != finfo.Size() {
			return fmt.Errorf("wrote %d, want %d", n, finfo.Size())
		}
	}
	
	return nil
 }


func client(u *user, params ...string) bool {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// hash con SHA512 de la contraseña
	keyClient := sha512.Sum512([]byte(u.password))
	keyLogin := keyClient[:32] // una mitad para el login (256 bits)
	keyData = keyClient[32:64] // la otra para los datos (256 bits)

	// generamos un par de claves (privada, pública) para el servidor
	pkClient, err := rsa.GenerateKey(rand.Reader, 1024)
	chk(err)
	pkClient.Precompute() // aceleramos su uso con un precálculo

	pkJSON, err := json.Marshal(&pkClient) // codificamos con JSON
	chk(err)

	keyPub := pkClient.Public()           // extraemos la clave pública por separado
	pubJSON, err := json.Marshal(&keyPub) // y codificamos con JSON
	chk(err)

	data := url.Values{} // estructura para contener los valores

	if len(params) == 0 {
		panic(1)
	}

	switch params[0] {

	case "register":
		data.Set("cmd", "register")          // comando (string)
		data.Set("user", u.userName)         // usuario (string)
		data.Set("pass", encode64(keyLogin)) // "contraseña" a base64

		// comprimimos y codificamos la clave pública
		data.Set("pubkey", encode64(compress(pubJSON)))

		// comprimimos, ciframos y codificamos la clave privada
		data.Set("prikey", encode64(encrypt(compress(pkJSON), keyData)))

	case "login":
		data.Set("cmd", "login")             // comando (string)
		data.Set("user", u.userName)         // usuario (string)
		data.Set("pass", encode64(keyLogin)) // "contraseña" a base64

	case "send":
		data.Set("cmd", "send")              // comando (string)
		data.Set("user", u.userName)         // usuario (string)
		data.Set("pass", encode64(keyLogin)) // "contraseña" a base64

		fN, err := json.Marshal(u.puntualFiles.FileNames)
		chk(err)

		eF, err := json.Marshal(u.puntualFiles.Files)
		chk(err)

		data.Set("fileNames", string(fN))
		data.Set("encryptedFiles", string(eF))
		data.Set("periodicity", "Archivos puntuales")

	case "sendFolder":

		data.Set("cmd", "sendFolder")        // comando (string)
		data.Set("user", u.userName)         // usuario (string)
		data.Set("pass", encode64(keyLogin)) // "contraseña" a base64

		fN, err := json.Marshal(u.folder.FileNames)
		chk(err)
		f, err := json.Marshal(u.folder.Files)
		chk(err)

		data.Set("fileNames", string(fN))     //nombre de los ficheros en la carpeta
		data.Set("encryptedFiles", string(f)) //ficheros encriptados de la carpeta

		if len(params) > 1 {
			i := len(u.Policies) - 1
			if PeriodicityType(params[1]) == DailyInHour{
				data.Set("periodicity", "Diaria a las " + strings.Replace(u.PoliciesOptionalValues[i], ":", "-", -1))
			}else{
				data.Set("periodicity", params[1])
			}
			data.Set("folder", u.Policies[i].PathFolder)
			data.Set("lastBackup", u.Policies[i].LastBackup.String())
			data.Set("nextBackup", u.Policies[i].NextBackup.String())
			data.Set("BackupType", string(u.Policies[i].BackupType))
		}

	case "automatedBackup":
		data.Set("cmd", "automatedBackup")   // comando (string)
		data.Set("user", u.userName)         // usuario (string)
		data.Set("pass", encode64(keyLogin)) // "contraseña" a base64

		if len(params) > 3 {
			data.Set("periodicity", params[1])
			data.Set("encryptedFiles", params[2])
			data.Set("fileNames", params[3])
			data.Set("positionPolicy", params[4])
		}
		if params[1] == "Sincronizado" {
			data.Set("lastBackup", params[5])
		}
	case "getListPeriodicity":
		data.Set("cmd", "getListPeriodicity") // comando (string)
		data.Set("user", u.userName)          // usuario (string)
		data.Set("pass", encode64(keyLogin))  // "contraseña" a base64

	case "getListBackups":
		data.Set("cmd", "getListBackups")    // comando (string)
		data.Set("user", u.userName)         // usuario (string)
		data.Set("pass", encode64(keyLogin)) // "contraseña" a base64

		if len(params) > 1 {
			data.Set("periodicity", params[1])
		}

	case "getBackup":
		data.Set("cmd", "getBackup")         // comando (string)
		data.Set("user", u.userName)         // usuario (string)
		data.Set("pass", encode64(keyLogin)) // "contraseña" a base64

		if len(params) > 3 {
			data.Set("backupName", params[1])
			data.Set("path", params[2])
			data.Set("periodicity", params[3])
		}
	case "updateConfigFile":
		data.Set("cmd", "updateConfigFile")         // comando (string)
		data.Set("user", u.userName)         // usuario (string)
		data.Set("pass", encode64(keyLogin)) // "contraseña" a base64
		
		if len(params) > 1{
			data.Set("policies", params[1])
		}

	}

	//r, err := client.PostForm("https://localhost:10443", data) // enviamos por POST
	d := bytes.NewBuffer([]byte(data.Encode()))
	req, err := http.NewRequest("POST", "https://localhost:10443", d)
	chk(err)

	r, err := client.Do(req)
	defer r.Body.Close()
	chk(err)

	switch params[0] {
	case "login":

		var target userServ
		storeBodyRequest(r.Body, &target)

		if(target.Ok){

			if len(target.ConfigurationFile) != 0 {

				k := sha512.Sum512([]byte(usuarioGlobal.password))
				decryptedUserData := decrypt(target.ConfigurationFile, k[:32])

				err = json.Unmarshal(decryptedUserData, &usuarioGlobal.Policies)
				chk(err)

			}

			return target.Ok
		}

		fmt.Println(target.Msg)
		return target.Ok


	case "getListPeriodicity", "getListBackups":
		var target responseListBackups
		storeBodyRequest(r.Body, &target)

		var backupFormat string
		if params[0] == "getListPeriodicity" {
			backupFormat = "periodicity"
		} else {
			backupFormat = "backup"
		}

		for _, file := range target.Backups {
			uiGeneral.Eval(fmt.Sprintf(`addOption(%q, %q)`, file, backupFormat))
		}

		return target.Ok

	case "getBackup":
		var target userFolder
		storeBodyRequest(r.Body, &target)

		key := sha512.Sum512([]byte(usuarioGlobal.password))
		dfile := decompress(decrypt(target.Files, key[:32]))
		ioutil.WriteFile(filepath.Join(target.Path, target.FileNames), dfile, 0644)
		untartar(target.FileNames, target.Path)
		err := os.Remove(filepath.Join(target.Path, target.FileNames)) 
		chk(err)

		return target.Ok

	default:
		var target response
		storeBodyRequest(r.Body, &target)

		if deletes, err := strconv.Atoi(target.Msg); err == nil{
			var policiesToDelete []int
			for indexPolicy, policy := range u.Policies{
				if(policy.Periodicity == DailySmartDelete || policy.Periodicity == WeeklySmartDelete || policy.Periodicity == MonthlySmartDelete){
					policiesToDelete = append(policiesToDelete, indexPolicy)
					deletes--
					if(deletes <= 0){
						break
					}
				}
			}

			for _,v := range policiesToDelete{
				u.deletePolicy(v)
			}
		}

		fmt.Println(target.Msg)
		return target.Ok
	}
}

//redirige a la pagina
func (r *redirection) redirect(s string) {
	r.Lock()
	defer r.Unlock()

	data, err := ioutil.ReadFile(s)
	if err != nil {
		log.Fatal(err)
	}

	str := string(data)
	loadableContents := "data:text/html," + url.PathEscape(str)
	uiGeneral.Load(loadableContents)
}

func (u *user) registerClient(userName string, password string) bool {
	u.Lock()
	defer u.Unlock()

	u.userName = userName
	u.password = password

	return client(u, "register")
}

func (u *user) sendCredentials(userName string, password string) bool {
	u.Lock()
	defer u.Unlock()

	u.userName = userName
	u.password = password

	s:= client(u, "login")
	if(s){
		go userDaemon()
	}
	return s
}

//Funcion para los archivos puntuales
func (fA *filesArray) openFiles(filesList []string, fileNames []string, numFiles int) {
	fA.Lock()
	defer fA.Unlock()

	var decodedFile []byte
	var encryptedFile []byte
	//	fA.FileNames = fileNames
	//fA.Files = make([][]byte, len(filesList))
	dataFile := make([][]byte, len(filesList))
	//key := sha512.Sum512([]byte(usuarioGlobal.password))

	for i := 0; i < numFiles; i++ {
		b64data := filesList[i][strings.IndexByte(filesList[i], ',')+1:]
		decodedFile = decode64(b64data)
		dataFile[i] = make([]byte, len(encryptedFile))
		dataFile[i] = decodedFile
		//encryptedFile = encrypt(compress(decodedFile), key[:32])
		//fA.Files[i] = make([]byte, len(encryptedFile))
		//fA.Files[i] = encryptedFile
	}

	fileNameTar := empaqueTarFicheros(dataFile, fileNames)
	file, err := os.Open(fileNameTar) // For read access.
	chk(err)
	fi, err := file.Stat()
	chk(err)
	data := make([]byte, fi.Size())
	chk(err)
	_, err = file.Read(data)
	chk(err)

	filesCompressedAEncrypted := encryptFilesTar(data)

	fA.Files = filesCompressedAEncrypted
	fA.FileNames = fi.Name()
	usuarioGlobal.puntualFiles = fA
	file.Close()
	err = os.RemoveAll(fileNameTar)
	chk(err)
	client(usuarioGlobal, "send")

}

func updateConfigFile(){
	policiesJSON, err := json.Marshal(usuarioGlobal.Policies)
	chk(err)

	key := sha512.Sum512([]byte(usuarioGlobal.password))
	encryptedPolicies := encrypt(policiesJSON, key[:32])

	client(usuarioGlobal, "updateConfigFile", string(encryptedPolicies))
}

func automatedBackup(policyNumber int) {
	usuarioGlobal.Lock()
	defer usuarioGlobal.Unlock()

	path := usuarioGlobal.Policies[policyNumber].PathFolder
	periodicity := usuarioGlobal.Policies[policyNumber].Periodicity

	//files := make([][]byte, 0)
	//fileNames := make([]string, 0)
	path = strings.Replace(path, "\\", "/", -1)

	uF := userFolder{}
	uF.Path = path
	usuarioGlobal.folder = &uF

	fileNameTar := empaqueTarCarpeta(path)
	file, err := os.Open(fileNameTar) // For read access.
	chk(err)
	fi, err := file.Stat()
	chk(err)
	data := make([]byte, fi.Size())
	chk(err)
	_, err = file.Read(data)
	chk(err)

	filesCompressedAEncrypted := encryptFilesTar(data)
	defer file.Close()

	fileS := filesCompressedAEncrypted
	fileName := fi.Name()
	//files, fileNames = addFiles(path, files, fileNames)
	//filesCompressedAEncrypted := encryptFiles(files)
	fN, err := json.Marshal(fileName)
	chk(err)
	f, err := json.Marshal(fileS)
	chk(err)
	var newLastBackup time.Time
	newLastBackup = time.Now()

	file.Close()
	err = os.RemoveAll(fileNameTar)
	chk(err)
	fmt.Println("Backup automatizado...")
	client(usuarioGlobal, "automatedBackup", string(periodicity), string(f), string(fN), strconv.Itoa(policyNumber), newLastBackup.String())
	usuarioGlobal.Policies[policyNumber].LastBackup = newLastBackup
}

func userDaemon() { //se ejecuta al inicio del programa, comprueba todas las policies del usuario
	c := time.Tick(PeriodicityCheckDuration)
	for next := range c {
		//fmt.Printf("%v %s\n", next, "comprobando si hay que hacer algun backup")
		//fmt.Println(usuarioGlobal.Policies)
		//fmt.Println("checkin...", next)
		year, month, day := next.Date()
		fmt.Printf("Comprobando si hay backups pendientes... Fecha: %02d/%02d/%d - %02d:%02d:%02d \n",
			day, month, year, next.Hour(), next.Minute(), next.Second())

		now := time.Now()
		for policyNumber, v := range usuarioGlobal.Policies {
			//Puedo acceder a v.PathFolder v.Periodicity v.BackupType v.LastBackup v.NextBackup
			if v.Periodicity == Sync {

				info, _ := os.Stat(v.PathFolder)
				timeParseado, _ := time.Parse("2006-01-02 15:04:05", strings.Split(strings.Split(info.ModTime().String(), ".")[0], " +0000")[0])
				timeParseadoBackup, _ := time.Parse("2006-01-02 15:04:05", strings.Split(strings.Split(v.LastBackup.String(), ".")[0], " +0000")[0])
				//fmt.Println(info.ModTime(), "...", timeParseado, "...", timeParseadoBackup)
				if timeParseado.After(timeParseadoBackup) {
					automatedBackup(policyNumber)
					updateConfigFile()
					// increment := v.NextBackup.Sub(v.LastBackup)
					// usuarioGlobal.Policies[policyNumber].NextBackup = v.NextBackup.Add(increment)
				}

			} else if v.Periodicity == DailyInHour {
				timeParseado, _ := time.Parse("2006-01-02 15:04:05", strings.Split(strings.Split(now.String(), ".")[0], " +0000")[0])
				timeParseadoBackup, _ := time.Parse("2006-01-02 15:04:05", strings.Split(strings.Split(v.NextBackup.String(), ".")[0], " +0000")[0])
				if timeParseado.After(timeParseadoBackup) {
					hour, min, sec := v.NextBackup.Clock()
					automatedBackup(policyNumber) //actualizo lastBackup en la función
					year, month, day := usuarioGlobal.Policies[policyNumber].LastBackup.AddDate(0,0,1).Date()
					usuarioGlobal.Policies[policyNumber].NextBackup = time.Date(year, month, day, hour, min, sec, 0, time.UTC)
					updateConfigFile()
				}
			}else {
				timeParseado, _ := time.Parse("2006-01-02 15:04:05", strings.Split(strings.Split(now.String(), ".")[0], " +0000")[0])
				timeParseadoBackup, _ := time.Parse("2006-01-02 15:04:05", strings.Split(strings.Split(v.NextBackup.String(), ".")[0], " +0000")[0])
				//	fmt.Printf(timeParseado.String() + " " + timeParseadoBackup.String())
				if timeParseado.After(timeParseadoBackup) {
					increment := v.NextBackup.Sub(v.LastBackup)
					automatedBackup(policyNumber) //actualizo lastBackup en la función
					usuarioGlobal.Policies[policyNumber].NextBackup = usuarioGlobal.Policies[policyNumber].LastBackup.Add(increment)
					updateConfigFile()
				}
			}

		}
	}
}

func (u *user) deletePolicy(policyIndex int) bool{
	delete(u.PoliciesOptionalValues, policyIndex)
	usuarioGlobal.Policies = append(usuarioGlobal.Policies[:policyIndex], usuarioGlobal.Policies[policyIndex+1:]...)
	updateConfigFile()
	return true
}

func (u *user) setPolicyOptionalValues(v string){
	u.PoliciesOptionalValues[len(u.Policies)] = v
	//for k, v := range u.PoliciesOptionalValues{
	//	fmt.Println(k, "---", v)
	//}
}

func addPolicy(path string, periodicity PeriodicityType, backupType BackupType) {

	var policy policyType

	policy.PathFolder = path
	policy.Periodicity = periodicity
	policy.BackupType = "completa"
	policy.LastBackup = time.Now()

	switch periodicity {
	case Daily, DailySmartDelete:
		policy.NextBackup = policy.LastBackup.Add(time.Hour * 24)
		//policy.NextBackup = policy.LastBackup.Add(time.Second * 10)
	case Weekly, WeeklySmartDelete:
		policy.NextBackup = policy.LastBackup.Add(time.Hour * 24 * 7)
	case Monthly, MonthlySmartDelete:
		policy.NextBackup = policy.LastBackup.Add(time.Hour * 24 * 30)
	case Sync:
		policy.NextBackup, _ = time.Parse("2006-01-02 15:04:05", "0") //tiempo 0
	case EveryXminutes:
		mins, err := strconv.Atoi(usuarioGlobal.PoliciesOptionalValues[len(usuarioGlobal.Policies)])
		chk(err)
		policy.NextBackup = policy.LastBackup.Add(time.Minute * time.Duration(mins))
	
	case DailyInHour:
		hourAndMinutesStr := usuarioGlobal.PoliciesOptionalValues[len(usuarioGlobal.Policies)]
		parts := strings.Split(hourAndMinutesStr, ":")
		
		hourStr := parts[0]
		hour, err := strconv.Atoi(hourStr)
		chk(err)
		
		minutesStr := parts[1]
		minutes, err := strconv.Atoi(minutesStr)
		chk(err)
		
		tomorrow := policy.LastBackup.AddDate(0, 0, 1) //Al día siguiente
		year, month, day := tomorrow.Date()
		policy.NextBackup = time.Date(year, month, day, hour, minutes, 0, 0, time.UTC)

	}
	if len(usuarioGlobal.Policies) >= maxPolicy {
		usuarioGlobal.Policies = usuarioGlobal.Policies[1:]
	}
	usuarioGlobal.Policies = append(usuarioGlobal.Policies, policy)

}

func encryptFiles(files [][]byte) [][]byte {
	filesCompressedAEncrypted := make([][]byte, len(files))
	key := sha512.Sum512([]byte(usuarioGlobal.password))

	for i, file := range files {
		filesCompressedAEncrypted[i] = encrypt(compress(file), key[:32])
	}

	return filesCompressedAEncrypted
}

func addFiles(path string, files [][]byte, fileNames []string) ([][]byte, []string) {

	err := filepath.Walk(path, func(pathF string, info os.FileInfo, err error) error {
		chk(err)

		if !info.IsDir() {
			data, err := ioutil.ReadFile(pathF)
			chk(err)
			if len(data) != 0 {
				files = append(files, data)
			}
		}

		fileNames = append(fileNames, pathF[strings.LastIndex(pathF, string(os.PathSeparator))+1:])

		return nil
	})
	chk(err)

	return files, fileNames
}
func encryptFilesTar(files []byte) []byte {
	filesCompressedAEncrypted := make([]byte, len(files))
	key := sha512.Sum512([]byte(usuarioGlobal.password))

	filesCompressedAEncrypted = encrypt(compress(files), key[:32])

	return filesCompressedAEncrypted
}



func (uF *userFolder) openFolder(path string, periodicity PeriodicityType) {
	uF.Lock()
	defer uF.Unlock()

	uF.Path = path
	usuarioGlobal.folder = uF
	//files := make([][]byte, 0)
	//fileNames := make([]string, 0)
	var incorrectFolder bool = false

	path = strings.Replace(path, "\\", "/", -1)

	_, err := os.Stat(path)
	if !os.IsNotExist(err) {
		//files, fileNames = addFiles(path, files, fileNames)
	} else {
		uiGeneral.Eval(fmt.Sprintf(`showError(%q)`, path))
		uiGeneral.Eval(`incorrectFolder = true`)
		incorrectFolder = true
	}

	if !incorrectFolder {
		fileNameTar := empaqueTarCarpeta(path)
		file, err := os.Open(fileNameTar) // For read access.
		chk(err)
		fi, err := file.Stat()
		chk(err)
		data := make([]byte, fi.Size())
		chk(err)
		_, err = file.Read(data)
		chk(err)

		filesCompressedAEncrypted := encryptFilesTar(data)
		defer file.Close()

		uF.Files = filesCompressedAEncrypted
		uF.FileNames = fi.Name()
		usuarioGlobal.folder = uF
		file.Close()
		err = os.RemoveAll(fileNameTar)
		chk(err)
		addPolicy(uF.Path, periodicity, "completa")
		client(usuarioGlobal, "sendFolder", string(periodicity))
		uiGeneral.Eval(`incorrectFolder = false`)
		updateConfigFile()
	}

}

func (u *user) getListPeriodicity() {
	client(u, "getListPeriodicity")
}

func (u *user) getListBackups(periodicity string) {
	client(u, "getListBackups", periodicity)
}

func (u *user) getBackup(periodicity string, backupName string, path string) {
	path = strings.Replace(path, "\\", "/", -1)
	client(u, "getBackup", backupName, path, periodicity)
}
func (u *user) getPolicies() map[string]string {
	var auxiliar map[string]string = make(map[string]string)
	auxiliar["len"] = strconv.Itoa(len(usuarioGlobal.Policies))
	for i := 0; i < len(usuarioGlobal.Policies); i++ {
		auxiliar["BackupType"+strconv.Itoa(i)] = string(usuarioGlobal.Policies[i].BackupType)
		auxiliar["lastBackup"+strconv.Itoa(i)] = strings.Split(strings.Split(usuarioGlobal.Policies[i].LastBackup.String(), ".")[0], "+0000")[0]
		if usuarioGlobal.Policies[i].Periodicity == Sync {
			auxiliar["nextBackup"+strconv.Itoa(i)] = "Sincronización Automática"

		} else {
			auxiliar["nextBackup"+strconv.Itoa(i)] = strings.Split(strings.Split(usuarioGlobal.Policies[i].NextBackup.String(), ".")[0], "+0000")[0]
		}
		auxiliar["folder"+strconv.Itoa(i)] = usuarioGlobal.Policies[i].PathFolder
		auxiliar["periodicity"+strconv.Itoa(i)] = string(usuarioGlobal.Policies[i].Periodicity)
	}
	return auxiliar
}

func main() {

	args := []string{}
	if runtime.GOOS == "linux" {
		args = append(args, "--class=Lorca")
	}

	//abro una ventana
	//parámetros de la funcion new => func New(url, dir string, width, height int, customArgs ...string)
	ui, err := lorca.New("", "", 1400, 700, args...)
	if err != nil {
		log.Fatal(err)
	}
	uiGeneral = ui
	defer ui.Close()

	// A simple way to know when UI is ready (uses body.onload event in JS)
	ui.Bind("start", func() {
		log.Println("UI is ready")
	})

	//u := &user{}
	usuarioGlobal = &user{PoliciesOptionalValues: make(map[int]string)}
	r := &redirection{}
	fA := &filesArray{}
	uF := &userFolder{}

	//parámetros de la función bind => nombre de la función en javascript, función en go
	ui.Bind("sendCredentials", usuarioGlobal.sendCredentials)
	ui.Bind("registerClient", usuarioGlobal.registerClient)
	ui.Bind("redirect", r.redirect)
	ui.Bind("openFiles", fA.openFiles)
	ui.Bind("openFolder", uF.openFolder)
	ui.Bind("getListPeriodicity", usuarioGlobal.getListPeriodicity)
	ui.Bind("getListBackups", usuarioGlobal.getListBackups)
	ui.Bind("getBackup", usuarioGlobal.getBackup)
	ui.Bind("getPolicies", usuarioGlobal.getPolicies)
	ui.Bind("setPolicyOptionalValues", usuarioGlobal.setPolicyOptionalValues)
	ui.Bind("deletePolicy", usuarioGlobal.deletePolicy)
	//leo el fichero
	data, err := ioutil.ReadFile("./www/index.html")
	if err != nil {
		log.Fatal(err)
	}

	//lo convierto a string
	str := string(data)
	loadableContents := "data:text/html," + url.PathEscape(str)
	//lo cargo en la interfaz
	ui.Load(loadableContents)

	//Para debugear javascript
	//ui.Eval(`console.log("Hello, world!");`)

	//Espero a que me llegue una señal o se cierre el navegador
	sigc := make(chan os.Signal)
	signal.Notify(sigc, os.Interrupt)
	select {
	case <-sigc:
	case <-ui.Done():
	}

	log.Println("exiting...")
}
