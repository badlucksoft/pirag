package pidb

import (
	"database/sql"
	"fmt"
	"log"
	"net"
	"strings"

	"pirag/settings"
	"pirag/prjiapi"

	"strconv"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

var (
	DBObj  *sql.DB
	Stmts  map[string]map[string]*sql.Stmt
	transx *sql.Tx
)

type SSHAttackID struct {
	AddrID   int64
	NameID   int64
	AttackID int64
	Found    bool
}

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
		defer stmt.Close()
	}
	defer DBObj.Close()
}
func tableExists(tv, tableName string) bool {
	var exists = false
	fmt.Printf("\ttable/view:\t%s\n\tname:\t%s\n", tv, tableName)
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
		createSSHErrorTable()
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
		stmt, err := DBObj.Prepare("select 1 as found from information_schema.tables where table_schema = '" + settings.AllSettings["DBName"] + "' and table_name=$1")
		Stmts["queries"]["table_existence"] = stmt
		if err != nil {
			log.Fatalf("MinPrepareStatements (MySQL); %s\n", err.Error())
		}
	case "postgres":
		stmt, err := DBObj.Prepare("select 1 as found from pg_tables where schemaname = 'public' and tablename=$1)")
		Stmts["queries"]["table_existence"] = stmt
		if err != nil {
			log.Fatalf("MinPrepareStatements (PostgreSQL); %s\n", err)
		}
	case "sqlite3":
		stmt, err := DBObj.Prepare("select 1 as found from sqlite_master where type=$1 and name=$2")
		Stmts["queries"]["table_existence"] = stmt
		if err != nil {
			log.Fatalf("MinPrepareStatements (SQLite3); %s\n", err)
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
		stmt, err = DBObj.Prepare("select attack_id,substr(attack_timestamp,0,20),del,addr_id,addr,name_id,username from ssh_attacks_view where del = 0 order by attack_timestamp limit $1 offset $2")
		Stmts["queries"]["get_ssh_attack_window"] = stmt
		if err != nil {
			log.Fatal(err)
		}
		stmt, err = DBObj.Prepare("select attack_id,substr(attack_timestamp,0,20),del,addr_id,addr,name_id,username from ssh_attacks_view where del = 0 order by attack_timestamp desc limit $1 offset $2")
		Stmts["queries"]["get_ssh_attack_window_rev"] = stmt
		if err != nil {
			log.Fatal(err)
		}
		stmt, err = DBObj.Prepare("insert into addr_table (addr) values ($1)")
		Stmts["queries"]["insert_addr"] = stmt
		stmt, err = DBObj.Prepare("select  addr_id, first_seen from addr_table where addr = $1")
		Stmts["queries"]["find_addr"] = stmt
		stmt, err = DBObj.Prepare("select attack_id,name_id, addr_id from ssh_attacks_view where attack_timestamp = $1 and lower(username) = lower($2) and addr = $3")
		Stmts["queries"]["check_for_ssh_attack"] = stmt
		stmt, err = DBObj.Prepare("insert into attacks_ssh (attack_timestamp,addr_id,name_id) values ($1,$2,$3)")
		Stmts["queries"]["insert_attack"] = stmt
		//attack_id , addr_id integer not null,name_id integer not null,attack_timestamp datetime not null, submit_timestamp datetime not null  default CURRENT_TIMESTAMP, error_message
		stmt, _ = DBObj.Prepare("insert into ssh_errors (attack_id,addr_id,name_id,attack_timestamp,submit_timestamp,error_message) select attack_id,addr_id,name_id,attack_timestamp,$1, $2 from attacks_ssh where attack_id = $3")
		Stmts["queries"]["report_ssh_error"] = stmt
		stmt, err = DBObj.Prepare("select name_id from username_table where lower(username) = lower($1)")
		Stmts["queries"]["find_username"] = stmt
		stmt, err = DBObj.Prepare("insert into username_table (username) values ($1)")
		Stmts["queries"]["insert_username"] = stmt
		Stmts["queries"]["flag_ssh_for_delete"], err = DBObj.Prepare("update attacks_ssh set del = 1 where attack_id = $1")
		Stmts["queries"]["purge_deleted_ssh"], err = DBObj.Prepare("delete from attacks_ssh where del = 1")
	}
}
func AddSSHAttack(attackTime string, addr_id, name_id int64) int64 {
	var id int64 = -1
	result, err := Stmts["queries"]["insert_attack"].Exec(attackTime, addr_id, name_id)
	if err == nil {
		id, _ = result.LastInsertId()
	} else {
		fmt.Printf("Error adding; %s\n", err)
	}
	return id
}
func RecordReportSSHError(attack_id, submitTime, errorMsg string) {
	ai, _ := strconv.Atoi(attack_id)
	Stmts["queries"]["report_ssh_error"].Exec(submitTime, errorMsg, ai)
	fmt.Printf("Moved attack_id %d to error table\n", ai)
}
func AttackExists(attackTime string, name, addr string) SSHAttackID {
	ids := SSHAttackID{-1, -1, -1, false}
	found := false
	row, err := Stmts["queries"]["check_for_ssh_attack"].Query(attackTime, name, addr)
	nxt := row.Next()
	if err == nil && nxt {
		defer row.Close()
		err = row.Scan(&ids.AttackID, &ids.NameID, &ids.AddrID)
		if ids.AttackID > 0 && err == nil {
			ids.Found = true
		} else {

			found, ids.NameID = FindUsername(name)
			found, ids.AddrID = FindIPAddr(addr)
		}
	} else {
		if err != nil {
			fmt.Printf("attack search error: %s (%s, %s, %s)\n", err, attackTime, name, addr)
		}
		found, ids.NameID = FindUsername(name)
		if found != false {
		}
		found, ids.AddrID = FindIPAddr(addr)
		if found != false {
		}
	}
	return ids
}
func FindUsername(username string) (bool, int64) {
	var id int64 = -1
	var found bool = false
	row, err := Stmts["queries"]["find_username"].Query(strings.TrimSpace(username))
	if err == nil && row.Next() {
		defer row.Close()
		err = row.Scan(&id)
		if err == nil {
			found = true
		}
	}
	return found, id
}
func AddUsername(username string) int64 {
	var id int64 = -1
	result, err := Stmts["queries"]["insert_username"].Exec(strings.TrimSpace(username))
	if err == nil {
		id, _ = result.LastInsertId()
	}
	return id
}
func FindIPAddr(addr string) (bool, int64) {
	var id int64 = -1
	var found bool = false
	row, err := Stmts["queries"]["find_addr"].Query(strings.TrimSpace(addr))
	if err == nil && row.Next() {
		var fs string
		err = row.Scan(&id, &fs)
		defer row.Close()
		if err == nil {
			found = true
		}
	}
	return found, id
}
func AddIPAddr(addr string) int64 {
	var id int64 = -1
	netAddrValue, ip := isNetAddr(strings.TrimSpace(addr))
	if netAddrValue && ip.IsLoopback() == false && ip.IsMulticast() == false && ip.IsGlobalUnicast() == true {

		result, err := Stmts["queries"]["insert_addr"].Exec(ip.String())
		if err == nil {
			id, _ = result.LastInsertId()
		}
	}
	return id
}

func isNetAddr(addr string) (bool, net.IP) {
	isIP := false
	var ip net.IP
	ipa, err := net.ResolveIPAddr("ip", strings.TrimSpace(addr))
	if err == nil {
		isIP = true
		ip = ipa.IP
	} else {
		fmt.Printf("Not IP address,%s  %s\n", addr, err)

	}
	return isIP, ip
}
func HandleReportResponses(responses []prjiapi.ReportResult) {
	fmt.Printf("%d report responses to process\n", len(responses))

	if len(responses) > 0 {
				BeginTX()
		for i := 0; i < len(responses); i++ {
			if responses[i].Success {
				fmt.Printf("SSH Attack ID %s was successful\n", responses[i].ID)
			} else {
				t := time.Now()
				RecordReportSSHError(responses[i].ID, t.UTC().Format("2006-01-02 15:04:05-06"), responses[i].Error)
				fmt.Printf("SSH Attack ID %s was failed: %s\n", responses[i].ID, responses[i].Error)

			}
			Stmts["queries"]["flag_ssh_for_delete"].Exec(responses[i].ID)
		}
		Stmts["queries"]["purge_deleted_ssh"].Exec()
				Commit()
	}
}
func GetSSHAttacks(count, page int, descending bool) []prjiapi.Report {
	var reports []prjiapi.Report
	var records *sql.Rows
	var err error
	if descending == false {
		records, err = Stmts["queries"]["get_ssh_attack_window"].Query(count, page*count)
	} else {
		records, err = Stmts["queries"]["get_ssh_attack_window_rev"].Query(count, page*count)
	}
	if err == nil {
		defer records.Close()
		for records.Next() {
			defer records.Close()
			var attack_id, addr_id, name_id, del int64
			var times, addr, username string 
			var at time.Time
			//attack_id,attack_timestamp,del,addr_id,addr,name_id,username
			records.Scan(&attack_id, &times, &del, &addr_id, &addr, &name_id, &username)
			at.In(time.UTC)
			at, _ = time.Parse("2006-01-02 15:04:05", times)
			reports = append(reports, prjiapi.Report{ID: strconv.FormatInt(attack_id, 10), IPAddress: addr, Username: username, Timestamp: at.Format(time.RFC3339)})
		}
	} else {
		log.Printf("GetSSHAttacks: unable to access attacks due to error: %s\n", err)
	}
	return reports
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
func createSSHErrorTable() {
	if tableExists("table", "ssh_errors") == false {
		fmt.Println("create ssh errors table")
		_, err := DBObj.Exec("CREATE TABLE ssh_errors (attack_id integer not null primary key autoincrement, addr_id integer not null,name_id integer not null,attack_timestamp datetime not null, submit_timestamp datetime not null  default CURRENT_TIMESTAMP, error_message text, del integer not null default 0)")
		if err == nil {
			fmt.Println("ssh errors table created")
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
		var err error
		if settings.AllSettings["DBSystem"] == "sqlite3" {
			_, err = DBObj.Exec("CREATE VIEW ssh_attacks_view as SELECT a.attack_id,substr(a.attack_timestamp,0,20) as attack_timestamp,a.del,a.addr_id,ad.addr,a.name_id,n.username FROM attacks_ssh a LEFT JOIN addr_table ad USING (addr_id) LEFT JOIN username_table n USING (name_id) order by attack_id")
		} else {
			_, err = DBObj.Exec("CREATE VIEW ssh_attacks_view as SELECT a.attack_id,a.attack_timestamp,a.del,a.addr_id,ad.addr,a.name_id,n.username FROM attacks_ssh a LEFT JOIN addr_table ad USING (addr_id) LEFT JOIN username_table n USING (name_id) order by attack_id")
		}
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
