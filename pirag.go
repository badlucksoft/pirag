package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"strconv"

	"pirag/logproc"
	"pirag/pidb"
	"pirag/prjiapi"
	"pirag/settings"
	"github.com/jamesruan/sodium"
	//"encoding/base64"
	//"github.com/jamesruan/sodium"
	//"encoding/json"
)

func main() {
	db := pidb.OpenDB()
	if pidb.DBObj == nil {
		pidb.SetDBObj(db)
		defer pidb.ShutdownDB()
		//fmt.Printf("just set DBObj: %v\n", pidb.DBObj)
	}
	if pidb.DBObj != nil {
		if settings.Command != "createdb" {
			pidb.PrepareStatements()
		} else {
			pidb.MinPrepareStatements()
		}
		defer pidb.ShutdownDB()
	} else {
		log.Fatal("DBObj is MIA")
	}
	//fmt.Printf("%v\n", pidb.Stmts)
	//fmt.Printf("settings file: %s\n", settings.SettingsFilename)
	//fmt.Printf("%q\n", settings.AllSettings)
	switch settings.Command {
	case "parselog":
		fmt.Println("parse ssh log file")
		logproc.ProcessSSHLog(settings.AllSettings["SSHLogFile"])
	case "createdb":
		fmt.Println("create database")
		pidb.CreateDatabase()
	case "createsettings":
		fmt.Printf("create settings file \"%s\".\n", settings.SettingsFilename)
		settings.CreateSettings()
	case "sendreport":
		fmt.Println("send report to prjindigo.com")
		reportSize, _ := strconv.Atoi(settings.AllSettings["ReportSize"])
		descending := false 
		if settings.AllSettings["ReportDesc"] == "1" {
			descending = true
		}
		reports := pidb.GetSSHAttacks(reportSize, 0, descending)
		if reports != nil && len(reports) > 0 {
			var sk prjiapi.ServerKeyRequest
			sk.RequestType = "RequestServerKey"
			fmt.Println("server key request type: ", sk.RequestType)
			skr := prjiapi.GetServerKeys()
			fmt.Printf("server keys: %v\n", skr)
			if prjiapi.VerifyServerKey(skr) {
				// perform next step
				fmt.Println("Server keys verified")
				//reportsJSON, _ := json.Marshal(reports)
				//fmt.Printf("reports JSON:\n%s\n", reportsJSON);
				prjiapi.PerformHandshake()

				response, err := prjiapi.SendAttackReport("ReportSSHAttack", reports[:])
				var responseJSON prjiapi.AttackReportResponse
				json.Unmarshal(response, &responseJSON)
				results, err := base64.StdEncoding.DecodeString(responseJSON.Result.EncryptedContent)
				resultNonce, err := base64.StdEncoding.DecodeString(responseJSON.Result.EncryptNonce)
				if err != nil {
					fmt.Printf("error with resultNonce: %s\n%v\n", err, resultNonce)
				}
				servkey, _ := base64.StdEncoding.DecodeString(prjiapi.SERVER_KEYS.EncryptPublicKey)
				privkey, _ := base64.StdEncoding.DecodeString(prjiapi.PRJI_PRIVATE_KEY)
				at, _ := prjiapi.PKDecrypt(results, resultNonce, sodium.BoxPublicKey{servkey}, sodium.BoxSecretKey{privkey})
				var rrs []prjiapi.ReportResult
				json.Unmarshal(at, &rrs)
				fmt.Printf("err: %s\nresponse: %v\n", err, rrs)
				pidb.HandleReportResponses(rrs)

			} else {
				fmt.Println("Server key verification failed.")
			}
		}
	default:
		fmt.Println("no valid command specified")
		flag.Usage()
	}
	/*
		var sk prjiapi.ServerKeyRequest
		sk.RequestType = "RequestServerKey"
		fmt.Println("server key request type: ", sk.RequestType)
		skr := prjiapi.GetServerKeys()
		if prjiapi.VerifyServerKey(skr) {
			// perform next step
			fmt.Println("Server keys verified")
			prjiapi.PerformHandshake()
			reports :=  [2]prjiapi.Report{{ID:"1",IPAddress:"192.168.6.24",Timestamp:"2019-04-19 23:23:23 EDT",Username:"RayTest"},{ID:"2",IPAddress:"172.16.6.24",Timestamp:"2019-04-19 23:23:23 EDT",Username:"RayTest"}}
			response,err := prjiapi.SendAttackReport("ReportSSHAttack",reports[:])
			var responseJSON prjiapi.AttackReportResponse
			json.Unmarshal(response,&responseJSON)
			results,err := base64.StdEncoding.DecodeString(responseJSON.Result.EncryptedContent)
			resultNonce,err := base64.StdEncoding.DecodeString(responseJSON.Result.EncryptNonce)
		servkey, _ := base64.StdEncoding.DecodeString(prjiapi.SERVER_KEYS.EncryptPublicKey)
		privkey, _ := base64.StdEncoding.DecodeString(prjiapi.PRJI_PRIVATE_KEY)
			at,_ := prjiapi.PKDecrypt(results,resultNonce,sodium.BoxPublicKey{servkey}, sodium.BoxSecretKey{privkey})
			var rrs []prjiapi.ReportResult
			json.Unmarshal(at,&rrs)
			fmt.Printf("err: %s\nresponse: %v\n",err,rrs)

		} else {
			fmt.Println("Server key verification failed.")
		}
	*/
}
