package settings

import (
	"bufio"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	DATABASE_TYPE_SSH_ONLY  = 0x01
	DATABASE_TYPE_WEB_ONLY  = 0x02
	DATABASE_TYPE_COMBINED  = 0x03
	default_database_type   = DATABASE_TYPE_COMBINED
	default_settings_file   = "pirag.settings"
	default_database_file   = "pirag.db"
	default_database_system = "sqlite3"
)

var (
	DatabaseSystem   string
	DatabaseHost     string
	DatabasePort     int
	DatabaseName     string
	DatabaseUser     string
	DatabaseFilename string
	DatabaseType     int
	SettingsFilename string
	Command          string
	SSHLogFile       string
	LogYear int
	AllSettings      map[string]string
)

func init() {
	AllSettings = make(map[string]string)
	AllSettings["ClientID"] = ""
	AllSettings["ClientSecret"] = ""
	AllSettings["PrivateKey"] = ""
	AllSettings["SigningKey"] = ""
	AllSettings["DBSystem"] = default_database_system
	AllSettings["SQLiteDB"] = default_database_file
	AllSettings["DBType"] = strconv.Itoa(default_database_type)
	AllSettings["DBHost"] = "localhost"
	AllSettings["DBPort"] = "0"
	AllSettings["DBUser"] = ""
	AllSettings["DBPassword"] = ""
	
	AllSettings["PGUseUUIDKeys"] = "0"
	AllSettings["SSHLogFile"] = "/var/log/secure"
	requestPassword := false

	//sql.Register("postgres",pq.Driver())	
	flag.StringVar(&DatabaseSystem, "dbsystem", default_database_system, "Database system: "+strings.Join(sql.Drivers(), ", "))
	flag.StringVar(&DatabaseFilename, "dbfile", default_database_file, "Database filename; only applicable for sqlite3 databases.")
	flag.IntVar(&DatabaseType, "dbtype", default_database_type, "Database type 1 SSH only, 2 web only, 3 combined")
	flag.StringVar(&SettingsFilename, "settings", default_settings_file, "Settings file name")
	flag.StringVar(&Command, "action", "", "createdb, createsettings, sendreport,parselog")
	flag.StringVar(&DatabaseHost, "dbhost", "localhost", "Database host name or address.")
	flag.IntVar(&DatabasePort, "dbport", 0, "Database port number")
	flag.StringVar(&DatabaseUser, "dbuser", "", "Database user name")
	flag.BoolVar(&requestPassword, "password", false, "Prompt for database password")
	flag.StringVar(&SSHLogFile, "securelog", AllSettings["SSHLogFile"], "Log file containing SSH failures.")
	flag.IntVar(&LogYear,"logyear",time.Now().Year(),"The year the log is from; defaults to current year.")
	flag.Parse()
	if Command != "" {
		Command = strings.ToLower(Command)
	}
	// read settings file and only overwrite settings that are at default values
	if ReadSettings() {
		fmt.Println("Settings read from file.")
	}
	if SSHLogFile != AllSettings["SSHLogFile"] {
		AllSettings["SSHLogFile"] = SSHLogFile
	}
	if DatabaseSystem != AllSettings["DBSystem"] {
		AllSettings["DBSystem"] = DatabaseSystem
	}
	if DatabaseFilename != AllSettings["SQLiteDB"] {
		AllSettings["SQLiteDB"] = DatabaseFilename
	}
	if asdbt, err := strconv.Atoi(AllSettings["DBType"]); err == nil && asdbt != DatabaseType {
		AllSettings["DBType"] = strconv.Itoa(DatabaseType)
	}
	if DatabaseHost != AllSettings["DBHost"] {
		AllSettings["DBHost"] = DatabaseHost
	}
	if asdbp, err := strconv.Atoi(AllSettings["DBPort"]); err == nil && asdbp != DatabasePort {
		AllSettings["DBPort"] = strconv.Itoa(DatabasePort)
	}
	if DatabaseUser != AllSettings["DBUser"] {
		AllSettings["DBUser"] = DatabaseUser
	}
	if requestPassword && AllSettings["DBType"] != "sqlite3" {
		fmt.Printf("Enter password user \"%s\": ", AllSettings["DBUser"])
		bytePassword, err := terminal.ReadPassword(0)
		if err == nil {
			AllSettings["DBPassword"] = string(bytePassword)
		}
	}
}

func ReadSettings() bool {
	settingsLoaded := false
	settingsFile, err := os.Open(SettingsFilename)
	if err == nil {
		defer settingsFile.Close()
		buf := bufio.NewScanner(settingsFile)
		cre := regexp.MustCompile(`^\s*(\S+\s*=([^\\#]|\\#?)*)?(#.*)?$`)
		re := regexp.MustCompile(`^(\w+)\s{0,}\=\s{0,}(.+)$`)
		for i := 1; buf.Scan(); i++ {
			line := cre.FindStringSubmatch(buf.Text())
			if line != nil && len(line) > 0 {
				data := re.FindStringSubmatch(line[1])
				if data != nil && len(data) > 0 {
					switch strings.ToLower(data[1]) {
					case "clientid":
						AllSettings["ClientID"] = strings.TrimSpace(data[2])
					case "clientsecret":
						AllSettings["ClientSecret"] = strings.TrimSpace(data[2])
					case "privatekey":
						AllSettings["PrivateKey"] = strings.TrimSpace(data[2])
					case "signingkey":
						AllSettings["SigningKey"] = strings.TrimSpace(data[2])
					case "dbsystem":
						AllSettings["DBSystem"] = strings.TrimSpace(data[2])
					case "sqlitedb":
						AllSettings["SQLiteDB"] = strings.TrimSpace(data[2])
					case "dbtype":
						AllSettings["DBType"] = strings.TrimSpace(data[2])
					case "dbhost":
						AllSettings["DBHost"] = strings.TrimSpace(data[2])
					case "dbport":
						AllSettings["DBPort"] = strings.TrimSpace(data[2])
					case "dbname":
						AllSettings["DBName"] = strings.TrimSpace(data[2])
					case "dbuser":
						AllSettings["DBUser"] = strings.TrimSpace(data[2])
					case "dbpassword":
						AllSettings["DBPassword"] = strings.TrimSpace(data[2])
					case "pguseuuidkeys":
						AllSettings["PGUseUUIDKeys"] = strings.TrimSpace(data[2])
					case "sshlogfile":
						AllSettings["SSHLogFile"] = strings.TrimSpace(data[2])
					}
				}
			}
		}
	}
	return settingsLoaded
}
func CreateSettings() bool {
	settingsCreated := false
	settingsFile, err := os.Create(SettingsFilename)
	if err == nil {
		defer settingsFile.Close()
		buf := bufio.NewWriter(settingsFile)
		buf.WriteString("ClientID=MyClientID\nClientSecret=MyDomainSecretHash\nPrivateKey=MyPrivateKey\nSigningKey=MySigningKey\nDBSystem=" + default_database_system + "\nSQLiteDB=" + default_database_file + "\nDBType=" + strconv.Itoa(default_database_type) + "\n" + "DBHost=localhost\nDBPort=0\nDBName=prjindigo\nDBUser=piuser\nDBPassword=someBetterPassw0rD\nPGUseUUIDKeys=0\nSSHLogFile=/var/log/secure\n")
		buf.Flush()
	} else {
		log.Fatal("Couldn't create settings file; " + SettingsFilename)
	}
	return settingsCreated
}
