package server

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/beevik/ntp"
	"github.com/labstack/echo"
	"io"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

var Save []Pkt

func main() {
	e := echo.New()

	e.GET("/", func(context echo.Context) error {
		t := Save
		Save = []Pkt{}
		return context.JSON(http.StatusOK,t)
	})

	// Start Bat
	// get IP
	type Ip struct {
		IP      string `json:"ip"`
	}
	var ipStruct Ip
	var err error
	resp,err := http.Get("https://ipinfo.io/")
	if err != nil{
		panic(err)
	}
	if err := json.NewDecoder(resp.Body).Decode(&ipStruct); err != nil{
		panic(err)
	}else{
		realIp = ipStruct.IP
	}
	fmt.Println(realIp)

	BaseTime,err = ntp.QueryWithOptions("time.google.com",ntp.QueryOptions{})
	if err != nil{
		panic(err)
	}

	//./pkt-recv -i en0 TCP.SRC_PORT==443 | ./pkt-txt2txt ETHERNET.TYPE==0x0800 | ./pkt-txt2txt TCP.FLAGS==0x002 # SYN
	//./pkt-recv -i en0 TCP.SRC_PORT==0x1bb | ./pkt-txt2txt ETHERNET.TYPE==0x0800 | ./pkt-txt2txt TCP.FLAGS==0x011 # FIN ACK
	cmdstr := "pkttools-1.16/pkt-recv -i en0 TCP.SRC_PORT==443"
	cmdstr2 := "pkttools-1.16/pkt-recv -i en0 TCP.DST_PORT==443"
	cmd := exec.Command("sh", "-c", cmdstr)
	cmd2 := exec.Command("sh", "-c", cmdstr2)
	//cmd := exec.Command("pkttools-1.16/pkt-recv", "-i","en0")

	go runCommand(cmd,&tempPkt)
	go runCommand(cmd2,&tempPkt2)

	e.Start(":8090")
}

var Num = map[string]int{
	"0": 0,
	"1": 1,
	"2": 2,
	"3": 3,
	"4": 4,
	"5": 5,
	"6": 6,
	"7": 7,
	"8": 8,
	"9": 9,
	"A": 10,
	"B": 11,
	"C": 12,
	"D": 13,
	"E": 14,
	"F": 15,
}

type Pkt struct {
	Time        int64 `json:"time"`
	Syn         bool      `json:"syn"`
	Fin         bool      `json:"fin"`
	DataLength  int  `json:"data_length"`
	Source      string    `json:"source"`
	Destination string    `json:"destination"`
	Tos         int `json:"tos"`
}

var tempPkt Pkt
var tempPkt2 Pkt

var realIp string

var tempIp string

var BaseTime *ntp.Response

func pktParse(line string,temp *Pkt){
	// パケットが完了している場合は変数を初期化。生成時刻を記録
	if line[:2] == "--"{
		temp = &Pkt{}
		return
	}
	// パケット終了
	if line == "=="{
		// TODO:ここで終了処理

		// SYNでもFINでもないパケットは破棄
		if !temp.Syn && !temp.Fin{
			return
		}
		j,err := json.Marshal(&temp)
		if err != nil{
			panic(err)
		}
		temp.Time = time.Now().Add(BaseTime.ClockOffset).UnixNano() //時刻記録
		fmt.Println(string(j))
		Save = append(Save,*temp)
		//fmt.Println("SendIP",temp.Source,"RecvIP",temp.Destination,"Status:Syn",temp.Syn,"Status:Fin",temp.Fin,"Time",temp.Time)
		return
	}
	// IPアドレス 送信元 TODO:ここはDHCPが有効だとローカルIPアドレスになる。
	if line[:6] == "000010"{
		ips := strings.Split(line[40:52]," ")
		ip := ""
		for n,i := range ips{
			if i == ""{
				continue
			}
			if n != 0{
				ip += "."
			}
			ip += strconv.Itoa(x0to10(i))
		}
		if ip[:7] == "192.168"{
			temp.Source = realIp
		}else{
			temp.Source = ip
		}
		//fmt.Println(ip,line[40:52])
	}
	// IPアドレス 送信先
	if line[:6] == "000010"{
		ips := strings.Split(line[53:58]," ")
		tempIp = ""
		for _,i := range ips{
			if i == ""{
				continue
			}
			if tempIp != ""{
				tempIp += "."
			}
			tempIp += strconv.Itoa(x0to10(i))
		}
		//fmt.Println(tempIp,line[52:58])
	}
	if line[:6] == "000020"{
		ips := strings.Split(line[8:13]," ")
		for _,i := range ips{
			if i == ""{
				continue
			}
			if tempIp != ""{
				tempIp += "."
			}
			tempIp += strconv.Itoa(x0to10(i))
		}
		if tempIp[:7] == "192.168"{
			temp.Destination = realIp
		}else{
			temp.Destination = tempIp
		}
		//fmt.Println(tempIp,line[8:13])
	}
	// FLAGS
	if line[:6] == "000020"{
		if line[56:58] == "02"{
			temp.Syn = true
			//log.Println("SYN")
		}
		if line[56:58] == "11"{
			temp.Fin = true
			//log.Println("FIN ACK")
		}
		//fmt.Println(temp.Syn,temp.Fin,line[56:58])
	}
	//fmt.Println(line)
}


func x0to10 (s string)int{
	if len(s) != 2{
		return 0
	}
	sum := Num[s[:1]] * 16
	sum += Num[s[1:]]
	return sum
}

func runCommand(cmd *exec.Cmd,temp *Pkt) {
	// stdoutのプロセスを取り出す的な
	outReader, err := cmd.StdoutPipe()
	if err != nil {
		return
	}

	// 読み取れるようにする
	var bufout  bytes.Buffer
	outReader2 := io.TeeReader(outReader, &bufout)

	// 実行
	if err = cmd.Start(); err != nil {
		return
	}

	// ここでstdour1行一行をスキャン
	go func(r io.Reader) {
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			pktParse(scanner.Text(),temp)
		}
	}(outReader2)

	// コマンド終了まで待つ
	err = cmd.Wait()
	return
}
