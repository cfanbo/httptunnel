/*
*

	客户端命令
	curl -p --proxy admin:123456@127.0.0.1:7777 https://www.baidu.com
*/
package main

import (
	"io"
	"log"
	"net"
	"net/http"
	"sync"
)

var (
	addr     = ":7777"
	username = "admin"
	password = "123456"
)

// tunnel 通道处理
func tunnel(w http.ResponseWriter, r *http.Request) {
	// 判断请求方法
	if r.Method != http.MethodConnect {
		log.Println(r.Method, r.RequestURI)
		http.NotFound(w, r) //404
		return
	}

	// 使用BasicAuth方式验证账户密码
	// 支持更多认证方法，需要根据客户端的访问方式调整，如直接读取请求头Authorization
	auth := r.Header.Get("Proxy-Authorization") //获取客户端授权信息
	r.Header.Set("Authorization", auth)
	u, p, ok := r.BasicAuth() //BasicAuth依赖Authorization
	if !ok || !(username == u || password == p) {
		log.Printf("bad credential: username %s or password %s\n", u, p)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	//连接远程服务器
	dstAddr := r.RequestURI
	dstConn, err := net.Dial("tcp", dstAddr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer dstConn.Close()

	//为客户端返回成功消息
	w.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))

	// HTTP是应用层协议，下层TCP是网络层协议，hijack可从HTTP Response获取TCP连接，若是HTTPS服务器则是TLS连接。
	// bio是带缓冲的读写者
	srcConn, bio, err := w.(http.Hijacker).Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer srcConn.Close()

	//创建两个goroutine
	wg := &sync.WaitGroup{}
	wg.Add(2)
	
	// 将TCP连接拷贝到HTTP连接中
	go func() {
		defer wg.Done()
		//缓存处理
		n := bio.Reader.Buffered()
		if n > 0 {
			n64, err := io.CopyN(dstConn, bio, int64(n))
			if n64 != int64(n) || err != nil {
				log.Printf("io.CopyN: %d %v\n", n64, err)
				return
			}
		}
		//进行全双工的双向数据拷贝(中继)
		io.Copy(dstConn, srcConn) //relay: src->dst
	}()

	// 将HTTP连接拷贝到TCP连接中
	go func() {
		defer wg.Done()
		//进行全双工的双向数据拷贝(中继)
		io.Copy(srcConn, dstConn) //relay:dst->src
	}()
	wg.Wait()
}

func main() {
	handler := http.HandlerFunc(tunnel)
	if err := http.ListenAndServe(addr, handler); err != nil {
		panic(err)
	}
}
