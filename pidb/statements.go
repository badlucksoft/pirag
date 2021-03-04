package pidb

import (
	"database/sql"
	"fmt"
	"log"
	"net"

	"github.com/badlucksoft/pirag/settings"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

var (
	DBObj  *sql.DB
	Stmts  map[string]map[string]*sql.Stmt
	transx *sql.Tx
)

func init() {
	Stmts = map[string]map[string]*sql.Stmt{}
	Stmts["db_creation"] = make(map[string]*sql.Stmt)
	Stmts["queries"] = make(map[string]*sql.Stmt)
	//	fmt.Printf("(db) settings: %v\n", settings.AllSettings)
	//	defer DBObj.Close()
}
func OpenDB() *sql.DB {
	connString := ""
	switch settings.AllSettings["DBSystem"] {
	case "mysql":
	case "postgres":
	case "sqlite3":
		connString = "file:" + settings.AllSettings["SQLiteDB"] + "?_fk=true&_auto_vacuum=1&_journal_mode=WAL"
	}
	db, err := sql.Open(settings.AllSettings["DBSystem"], connString)
	if err == nil {
		db.Ping()
		DBObj = db
		//	fmt.Printf("DBObj %v\n", DBObj)
		//prepareStatements()
	} else {
		log.Fatal(err)
	}
	return db
}
func SetDBObj(D *sql.DB) {
	DBObj = D
}
func BeginTX() *sql.Tx {
	transx, err := DBObj.Begin()
	if err != nil || transx == nil {
		fmt.Printf("Error starting transaction; %s\n", err)
	}
	return transx
}
func Commit() {
	if transx != nil {
		transx.Commit()
	}
}
func ShutdownDB() {
	for _, stmt := range Stmts["queries"] {
		stmt.Close()
	}
	DBObj.Close()
}
func tableExists(tv, tableName string) bool {
	var exists = false
	fmt.Printf("\ttabele/view:\t%s\n\tname:\t%s\n", tv, tableName)
	result, err := Stmts["queries"]["table_existence"].Query(tv, tableName)
	fmt.Printf("tableExists %v\n%v\n", result, err)
	result.Next()
	var e int
	result.Scan(&e)
	fmt.Printf("exists %d\n", e)
	if e == 1 {
		exists = true
	}
	if err != nil {
		log.Printf("error %v\n", err)
	}
	result.Close()
	//	Stmts["queries"]["table_existence"].Close()
	return exists
}

/*
CreateDatabase creates a database with configured parameters.
*/
func CreateDatabase() {
	fmt.Println("Creating database...")
	createInfoTable()
	createUsernameTable()
	createAddrTable()
	switch settings.AllSettings["DBType"] {
	case "1":
		createSSHTable()
		createSSHView()
	case "2":
		//	createPasswordTable()
		create404Table()
		createWebAttackTable()
		createWebLoginTable()
	case "3":
		createSSHTable()
		createSSHView()
		//		createPasswordTable()
		create404Table()
		createWebAttackTable()
		createWebLoginTable()
	}
}

func MinPrepareStatements() {
	switch settings.AllSettings["DBSystem"] {
	case "mysql":
		//fmt.Println("MySQL database")
		stmt, err := DBObj.Prepare("select 1 as found from information_schema.tables where table_schema = '" + settings.AllSettings["DBName"] + "' and table_name=$1")
		Stmts["queries"]["table_existence"] = stmt
		if err != nil {
			log.Fatal("line 102; " + err.Error())
		}
	case "postgres":
		//	fmt.Println("PostgreSQL database")
		stmt, err := DBObj.Prepare("select 1 as found from pg_tables where schemaname = 'public' and tablename=$1)")
		Stmts["queries"]["table_existence"] = stmt
		if err != nil {
			log.Fatal(err)
		}
	case "sqlite3":
		//	fmt.Printf("SQLite3 database\n%p\n", DBObj)
		stmt, err := DBObj.Prepare("select 1 as found from sqlite_master where type=$1 and name=$2")
		Stmts["queries"]["table_existence"] = stmt
		if err != nil {
			log.Fatal(err)
		}
	}
}

/*
PrepareStatements Creates prepared statements for later, and possible repeated, execution.
*/
func PrepareStatements() {
	MinPrepareStatements()
	fmt.Printf("DBObj (prepareStatements) %v\n", DBObj)

	switch settings.AllSettings["DBSystem"] {
	case "mysql":
		fmt.Println("MySQL database")
		/*
			stmt, err := DBObj.Prepare("select 1 as found from information_schema.tables where table_schema = '" + settings.AllSettings["DBName"] + "' and table_name=$1")
			Stmts["queries"]["table_existence"] = stmt
			if err != nil {
				log.Fatal("line 102; " + err.Error())
			}
		*/
	case "postgres":
		fmt.Println("PostgreSQL database")
		/*
			stmt, err := DBObj.Prepare("select 1 as found from pg_tables where schemaname = 'public' and tablename=$1)")
			Stmts["queries"]["table_existence"] = stmt
			if err != nil {
				log.Fatal(err)
			}
		*/
	case "sqlite3":
		fmt.Printf("SQLite3 database\n%p\n", DBObj)
		/*
			stmt, err := DBObj.Prepare("select 1 as found from sqlite_master where type=$1 and name=$2")
			Stmts["queries"]["table_existence"] = stmt
			if err != nil {
				log.Fatal(err)
			}
		*/
		stmt, err := DBObj.Prepare("update attacks_ssh set del=1 where attack_id=$1")
		Stmts["queries"]["mark_ssh_row_for_del"] = stmt
		if err != nil {
			log.Fatal(err)
		}
		stmt, err = DBObj.Prepare("update alogin set del=1 where alogin_id=$1")
		Stmts["queries"]["mark_login_row_for_del"] = stmt
		if err != nil {
			log.Fatal(err)
		}
		stmt, err = DBObj.Prepare("update a404 set del=1 where a404_id=$1")
		Stmts["queries"]["mark_404_row_for_del"] = stmt
		if err != nil {
			log.Fatal(err)
		}
		stmt, err = DBObj.Prepare("update aweb set del=1 where aweb_id=$1")
		Stmts["queries"]["mark_web_row_for_del"] = stmt
		if err != nil {
			log.Fatal(err)
		}
		stmt, err = DBObj.Prepare("select * from ssh_attacks_view where del = 0 order by attack_timestamp limit $1 offset $2")
		Stmts["queries"]["get_ssh_attack_window"] = stmt
		if err != nil {
			log.Fatal(err)
		}
	}
}
func FindUsername(username string) (bool, int) {
	var id int = -1
	var found bool = false
	return found, id
}
func AddUsername(username string) int {
	var id int = -1
	return id
}
func FindIPAddr(addr string) (bool, int) {
	var id int = -1
	var found bool = false
	return found, id
}
func AddIPAddr(addr string) int {
	var id int = -1
	return id
}
func isNetAddr(addr string) (bool, net.IP) {
	isIP := false
	var ip net.IP
	ipa, err := net.ResolveIPAddr("ipv4", addr)
	if err == nil {
		isIP = true
		ip = ipa.IP
	} else {
		if ipa, err = net.ResolveIPAddr("ipv6", addr); err == nil {
			isIP = true
			ip = ipa.IP
		}
	}
	return isIP, ip
}

func GetAddressID(addr string) int {
	addrID := -1
	netAddrValue, ip := isNetAddr(addr)
	if netAddrValue && ip.IsLoopback() == false && ip.IsMulticast() == false && ip.IsGlobalUnicast() == true {

	}
	return addrID
}
func GetSSHAttacks(count, page int) {
	records, err := Stmts["queries"]["get_ssh_attack_window"].Query(count, page*count)
	if err == nil {
		fmt.Printf("records: %v\n", records)
		defer records.Close()
		for records.Next() {
			var attack_id, addr_id, name_id, del int
			var timestamp, addr, username string
			//attack_id,attack_timestamp,del,addr_id,addr,name_id,username
			records.Scan(&attack_id, &timestamp, &del, &addr_id, &addr, &name_id, &username)
			//		fmt.Printf("rec err: %v\n", recerr)
			fmt.Printf("attack id: %d\naddr id: %d\nname id: %d\ntimestamp: %s\n,addr: %s\nname: %s\ndel: %d\n", attack_id, addr_id, name_id, timestamp, addr, username, del)
		}
	} else {
		log.Println(err)
	}
}
func createAddrTable() {
	if tableExists("table", "addr_table") == false {
		fmt.Println("create address table")
		_, err := DBObj.Exec("CREATE TABLE addr_table (addr_id integer not null primary key autoincrement, addr varchar(64) not null, first_seen datetime not null default CURRENT_TIMESTAMP)")
		if err == nil {
			fmt.Println("address table created")
		} else {
			log.Fatal(err)
		}
	} else {
		fmt.Println("address table exists")
	}
}

func createSSHTable() {
	if tableExists("table", "attacks_ssh") == false {
		fmt.Println("create ssh attacks table")
		_, err := DBObj.Exec("CREATE TABLE attacks_ssh (attack_id integer not null primary key autoincrement, addr_id integer not null,name_id integer not null,attack_timestamp datetime not null default CURRENT_TIMESTAMP, del integer not null default 0)")
		if err == nil {
			fmt.Println("ssh attacks table created")
		} else {
			log.Fatal(err)
		}
	} else {
		fmt.Println("ssh attacks table exists")
	}
}
func createSSHView() {
	if tableExists("view", "ssh_attacks_view") == false {
		fmt.Println("create ssh attacks view")
		_, err := DBObj.Exec("CREATE VIEW ssh_attacks_view as SELECT a.attack_id,a.attack_timestamp,a.del,a.addr_id,ad.addr,a.name_id,n.username FROM attacks_ssh a LEFT JOIN addr_table ad USING (addr_id) LEFT JOIN username_table n USING (name_id)")
		if err == nil {
			fmt.Println("ssh attacks view created")
		} else {
			log.Fatal(err)
		}
	} else {
		fmt.Println("ssh attacks view exists")
	}
}

func createUsernameTable() {
	if tableExists("table", "username_table") == false {
		fmt.Println("create usernames table")
		_, err := DBObj.Exec("CREATE TABLE username_table (name_id integer not null primary key autoincrement, username varchar(100) not null,first_seen datetime not null default CURRENT_TIMESTAMP);")
		if err == nil {
			fmt.Println("address table created")
		} else {
			log.Fatal(err)
		}
	} else {
		fmt.Println("usernames table exists")
	}
}

func createPasswordTable() {
	if tableExists("table", "passwords") == false {
		fmt.Println("create passwords table")
	} else {
		fmt.Println("passwords table exists")
	}
}

func createWebLoginTable() {
	if tableExists("table", "attacks_login") == false {
		fmt.Println("create login table")

		_, err := DBObj.Exec("CREATE TABLE alogin (alogin_id integer primary key autoincrement,un varchar(40),pw varchar(40),cookie_content text,get_content text,post_content text,useragent text,referrer text,atk_timestamp datetime not null default CURRENT_TIMESTAMP,addr_id integer not null, del integer not null default 0, foreign key(addr_id) references addrs (addr_id) on delete cascade on update cascade)")
		if err == nil {
			fmt.Println("address table created")
		} else {
			log.Fatal(err)
		}
	} else {
		fmt.Println("login table exists")
	}
}

func create404Table() {
	if tableExists("table", "a404") == false {
		fmt.Println("create 404 table")
		_, err := DBObj.Exec("CREATE TABLE a404 (a404_id integer primary key autoincrement, requested_uri text not null,cookie_content text,get_content text,post_content text,useragent text,referrer text,atk_timestamp datetime not null default CURRENT_TIMESTAMP, addr_id integer not null, del integer not null default 0, foreign key(addr_id) references addrs (addr_id) on delete cascade on update cascade)")
		if err == nil {
			fmt.Println("404 table created")
		} else {
			log.Fatal(err)
		}
	} else {
		fmt.Println("404 table exists")
	}
}

func createWebAttackTable() {
	if tableExists("table", "attacks_web") == false {
		fmt.Println("create web attacks table")
		_, err := DBObj.Exec("CREATE TABLE aweb (aweb_id integer primary key autoincrement,request_uri text not null,cookie_content text, get_content text,post_content text,useragent text,referrer text,atk_timestamp datetime not null default CURRENT_TIMESTAMP,addr_id integer not null, del integer not null default 0, foreign key(addr_id) references addrs (addr_id) on delete cascade on update cascade)")
		if err == nil {
			fmt.Println("web attacks table created")
		} else {
			log.Fatal(err)
		}
	} else {
		fmt.Println("web attacks table exists")
	}

}

func createInfoTable() {
	if tableExists("table", "settings") == false {
		fmt.Println("create settings table")
	} else {
		fmt.Println("settings table exists")
	}
}
