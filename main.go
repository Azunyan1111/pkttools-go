package main

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/beevik/ntp"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"
)


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
	SendAddr string
	RecvAddr string
	Syn bool
	Fin bool
	Time time.Time
}

var tempPkt Pkt

var tempIp string

var BaseTime *ntp.Response

func main() {
	var err error
	BaseTime,err = ntp.QueryWithOptions("time.google.com",ntp.QueryOptions{})
	if err != nil{
		panic(err)
	}

	//./pkt-recv -i en0 TCP.SRC_PORT==443 | ./pkt-txt2txt ETHERNET.TYPE==0x0800 | ./pkt-txt2txt TCP.FLAGS==0x002 # SYN
	//./pkt-recv -i en0 TCP.SRC_PORT==0x1bb | ./pkt-txt2txt ETHERNET.TYPE==0x0800 | ./pkt-txt2txt TCP.FLAGS==0x011 # FIN ACK
	cmdstr := "pkttools-1.16/pkt-recv -i en0 TCP==443"
	cmd := exec.Command("sh", "-c", cmdstr)
	//cmd := exec.Command("pkttools-1.16/pkt-recv", "-i","en0")
	runCommand(cmd)
}


func pktParse(line string){
	// パケットが完了している場合は変数を初期化。生成時刻を記録
	if line[:2] == "--"{
		tempPkt = Pkt{}
		tempPkt.Time = time.Now().Add(BaseTime.ClockOffset) //時刻記録
		return
	}
	// パケット終了
	if line == "=="{
		// TODO:ここで終了処理

		// SYNでもFINでもないパケットは破棄
		if !tempPkt.Syn && !tempPkt.Fin{
			return
		}
		fmt.Println("SendIP",tempPkt.SendAddr,"RecvIP",tempPkt.RecvAddr,"Status:Syn",tempPkt.Syn,"Status:Fin",tempPkt.Fin,"Time",tempPkt.Time.Unix())
		return
	}
	// IPアドレス 送信元 TODO:ここはDHCPが有効だとローカルIPアドレスになる。
	if line[:6] == "000010"{
		ips := strings.Split(line[40:52]," ")
		ip := ""
		for n,i := range ips{
			if n != 0{
				ip += "."
			}
			ip += strconv.Itoa(x0to10(i))
		}
		tempPkt.SendAddr = ip
		//fmt.Println(ip,line[40:52])
	}
	// IPアドレス 送信先
	if line[:6] == "000010"{
		ips := strings.Split(line[53:58]," ")
		tempIp = ""
		for _,i := range ips{
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
			if tempIp != ""{
				tempIp += "."
			}
			tempIp += strconv.Itoa(x0to10(i))
		}
		tempPkt.RecvAddr = tempIp
		//fmt.Println(tempIp,line[8:13])
	}
	// FLAGS
	if line[:6] == "000020"{
		if line[56:58] == "02"{
			tempPkt.Syn = true
			//log.Println("SYN")
		}
		if line[56:58] == "11"{
			tempPkt.Fin = true
			//log.Println("FIN ACK")
		}
		//fmt.Println(tempPkt.Syn,tempPkt.Fin,line[56:58])
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

func runCommand(cmd *exec.Cmd) {
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
			pktParse(scanner.Text())
		}
	}(outReader2)

	// コマンド終了まで待つ
	err = cmd.Wait()
	return
}
