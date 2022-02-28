package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"strconv"
)

var port = flag.String("port", "10800", "socks5绑定的本地端口")

func Socks5Auth(client net.Conn)  (err error){
	//获取数据切片
	buf := make([]byte, 256)

	//读取前两个字节，判断协议版本
	n, err := io.ReadFull(client, buf[:2])
	if err != nil || n !=2 {
		fmt.Println("reading socks header false!")
	}
	ver, nMethods := int(buf[0]), int(buf[1])

	fmt.Printf("Current Socks Version is :%d\n", ver)

	// 读取 METHODS 列表
	n, err = io.ReadFull(client, buf[:nMethods])
	if n != nMethods {
		return errors.New("reading methods: " + err.Error())
	}

	//0x00即为无需认证模式
	n, err = client.Write([]byte{0x05, 0x00})
	if n != 2 || err != nil {
		return errors.New("write rsp: " + err.Error())
	}
	return nil
}


func Socks5Connect(client net.Conn) (target net.Conn, err error){
	buf := make([]byte, 256)
	n, err := io.ReadFull(client, buf[:4])
	addr := ""

	if err != nil  || n != 4 {
		fmt.Println("reading socks header false!")
	}

	ver, cmd, _, atyp := buf[0], buf[1], buf[2], buf[3]

	if ver != 5 || cmd != 1 {
		return nil, errors.New("invalid ver/cmd")
	}

	switch atyp {
	case 0x01:
		//ipv4形式
		n, err := io.ReadFull(client, buf[:4])
		if err != nil || n != 4{
			return nil, errors.New("IPV4 get error")
		}
		addr = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
	case 0x03:
		//域名形式
		n, err := io.ReadFull(client, buf[:1])
		if err != nil || n != 4{
			return nil, errors.New("Hostname get error")
		}
		hostLen := int(buf[0])

		n, err = io.ReadFull(client, buf[hostLen:])
		if err != nil || n != hostLen{
			return nil, errors.New("Hostname get error")
		}

		addr = string(buf[:hostLen])
	case 0x04:
		return nil, errors.New("Could not Support IPV6!")
	}

	n, err = io.ReadFull(client, buf[:2])
	if n != 2 {
		return nil, errors.New("read port: " + err.Error())
	}
	port := binary.BigEndian.Uint16(buf[:2])

	destAddrPort := fmt.Sprintf("%s:%d", addr, port)
	dest, err := net.Dial("tcp", destAddrPort)
	if err != nil {
		return nil, errors.New("dial dst: " + err.Error())
	}

	//响应给客户端，连接成功
	n, err = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	if err != nil {
		dest.Close()
		return nil, errors.New("write rsp: " + err.Error())
	}

	return dest, nil
}

func relay(from ,to net.Conn) {
	defer from.Close()
	defer to.Close()
	io.Copy(from, to)
}

func process(client net.Conn)  {
	//服务端声明认证方式以及协议号
	if err := Socks5Auth(client); err != nil{
		fmt.Println("Auth error", err.Error())
		client.Close()
		return
	}
	dest, err := Socks5Connect(client)
	//向target进行tcp连接
	if err != nil{
		fmt.Println("Connect error", err.Error())
		client.Close()
		return
	}

	//实现全双工
	go relay(client, dest)
	go relay(dest, client)
}


func Run(addr string)  {
	server, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Printf("Listen failed: %v\n", err)
		return
	}

	fmt.Printf("[+]Socks5 Server Start at: 0.0.0.0%s\n", addr)

	for {
		client, err := server.Accept()
		if err != nil {
			fmt.Printf("Accept failed: %v", err)
			continue
		}
		go process(client)
	}
}


func main() {
	flag.Parse()
	port, err :=strconv.Atoi(*port)
	if err != nil || port < 0 || port > 65535 {
		fmt.Println("输入端口有误")
		return
	}
	addr := fmt.Sprintf(":%s", strconv.Itoa(port))
	Run(addr)
}