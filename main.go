package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/miekg/dns"
	"golang.org/x/net/idna"
)

var whoisservers map[string]string
var domaintlds []string

type config struct {
	Ips   []string `toml:"ip"`
	Port  string   `toml:"port"`
	Front string   `toml:"front"`
}

var whois_config config

var nserverre = regexp.MustCompile(`nserver:\s+(.*?)\s`)

func checkdomainnameserver(domain string) string {
	returnhtml := ""
	whoiscontent := whoisquery("ianawhois.vip.icann.org", domain)
	if strings.Contains(whoiscontent, "0 objects") {
		returnhtml = "May be you enter the wrong domain?\n"
		return returnhtml
	}
	//fmt.Println(whoiscontent)
	//nserverre := regexp.MustCompile(`nserver:\s+.*?\s+(.*?)\s+`)
	nserver := nserverre.FindStringSubmatch(whoiscontent)
	if len(nserver) == 0 {
		return ""
	}
	//fmt.Println(nserver[1])
	// log.Println(nserver)
	// ipa, _ := net.LookupIP(string(nserver))
	// if len(ipa) == 0 {
	// 	returnhtml += "get nameserver failed\n"
	// } else {
	// r := &net.Resolver{
	// 	PreferGo: true,
	// 	Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
	// 		d := net.Dialer{
	// 			Timeout: time.Millisecond * time.Duration(10000),
	// 		}
	// 		return d.DialContext(ctx, "tcp", nserver[1]+":53")
	// 	},
	// }
	// domainnameservers, _ := r.LookupNS(context.Background(), domain)
	myReq := new(dns.Msg)
	myReq.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	c := new(dns.Client)
	c.Net = "udp"
	nserversingle := net.JoinHostPort(nserver[1], "53")
	// if strings.Contains(nserver[1], ":") {
	// 	nserversingle = "[" + nserver[1] + "]"
	// } else {
	// 	nserversingle = nserver[1]
	// }
	r, _, _ := c.Exchange(myReq, nserversingle)
	log.Println(nserversingle, domain)
	//log.Println(r)
	returnhtml += "Dns info:\n"
	if len(r.Answer) > 0 {
		for _, domainanswer := range r.Answer {
			returnhtml += domainanswer.String() + "\n"
		}
	}
	if len(r.Ns) > 0 {
		for _, domainnameserver := range r.Ns {
			returnhtml += domainnameserver.String() + "\n"
		}
		for _, dnshost := range r.Extra {
			returnhtml += dnshost.String() + "\n"
		}

		// if strings.Contains(returnhtml, "."+domain) {
		// 	myReq = new(dns.Msg)
		// 	myReq.SetQuestion(dns.Fqdn(domain), dns.TypeA)
		// 	c := new(dns.Client)
		// 	c.Net = "udp"
		// 	nserversingle = net.JoinHostPort(nserver[1], "53")
		// 	r, _, _ = c.Exchange(myReq, nserversingle)
		// 	r.AuthenticatedData
		// 	if len(r.Extra) > 0 {
		// 		for _, dnshost := range r.Extra {
		// 			returnhtml += dnshost.String() + "\n"
		// 		}
		// 	}

		// }
	} else {
		returnhtml += "The domain has no nameserver, check whois status.\n"
	}
	//}

	returnhtml += "---------------------\n"
	return returnhtml
}
func whoisquery(server string, domain string) string {
	whoiscontent := ""
	conn, err := net.Dial("tcp", server+":43")
	if err != nil {
		fmt.Println("err : ", err)
		return err.Error()
	}
	defer conn.Close()
	inputInfo := domain + "\r\n"
	_, err = conn.Write([]byte(inputInfo))
	if err != nil {
		return err.Error()
	}
	for {
		buf := [512]byte{}
		n, err := conn.Read(buf[:])
		if err != nil {
			if err == io.EOF {
				whoiscontent += string(buf[:n])
				return whoiscontent
			}
			return err.Error()
		}
		whoiscontent += string(buf[:n])
	}
}
func IsNum(s string) bool {
	_, err := strconv.ParseFloat(s, 64)
	return err == nil
}
func requestHandler(w http.ResponseWriter, r *http.Request) {
	httporigin := r.Header.Get("origin")
	if !strings.HasPrefix(httporigin, whois_config.Front) && !strings.Contains(httporigin, "127.0.0.1:"+whois_config.Port) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	r.ParseForm()
	xForwardedFor := r.Header.Get("X-Forwarded-For")
	ip := strings.TrimSpace(strings.Split(xForwardedFor, ",")[0])
	if ip == "" {
		ip, _, _ = net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	}
	domain := r.Form.Get("domain")
	returnhtml := "err "
	if domain != "" {
		domain, _ = idna.ToASCII(domain)
		domain = strings.ToLower(domain)
		whoisserver := ""
		for _, v := range domaintlds {
			// if domain == v || "."+domain == v {
			// 	break
			// }
			if strings.HasSuffix(domain, v) {
				whoisserver = whoisservers[v]
				log.Println(domain + ":" + whoisserver + ":" + ip)
				break
			}
		}
		if whoisserver == "" {
			whoisserver = "ianawhois.vip.icann.org"
		}
		whoiscontent := ""

		globalwhoisserver := ""
		if strings.Contains(whoisserver, ":/") {
			returnhtml = checkdomainnameserver(domain)
			returnhtml += "This domain does not provide a whois server. Please visit <a href='" + whoisserver + "'>" + whoisserver + "</a> to get more info."

		} else {
			reg, _ := regexp.Compile(`whois:.*   (.*)`)
			ipserver, _ := regexp.Compile(`ResourceLink:(\s|\w|\.)+\n`)
			if whoisserver == "ianawhois.vip.icann.org" {
				for whoisserver != "" {
					tmpwhoiscontent := whoisquery(whoisserver, domain)
					whoiscontent = tmpwhoiscontent
					if !strings.Contains(domain, ".") && !strings.HasPrefix(domain, "as") && !strings.Contains(domain, ":") && !IsNum(domain) {
						globalwhoisserver = whoisserver
						break
					}
					if len(reg.FindAllString(tmpwhoiscontent, -1)) > 0 {
						whoisserverxx := strings.Split(reg.FindAllString(tmpwhoiscontent, -1)[0], " ")
						whoisserver = strings.TrimSpace(whoisserverxx[len(whoisserverxx)-1])
						globalwhoisserver = whoisserver
					} else if len(ipserver.FindAllString(tmpwhoiscontent, -1)) > 0 {
						whoisserverxx := strings.Split(ipserver.FindAllString(tmpwhoiscontent, -1)[0], " ")
						whoisserver = strings.TrimSpace(whoisserverxx[len(whoisserverxx)-1])
						globalwhoisserver = whoisserver
					} else {
						whoisserver = ""
					}
				}
			} else {
				tmpwhoiscontent := whoisquery(whoisserver, domain)
				whoiscontent = tmpwhoiscontent
				globalwhoisserver = whoisserver
			}

			if globalwhoisserver == "" || globalwhoisserver == "ianawhois.vip.icann.org" {
				if strings.Contains(whoiscontent, "0 objects") {
					returnhtml = "May be you enter the wrong domain?\n"
					log.Println(domain + " wrong domain")
				} else {
					returnhtml = "There is no whois server for this domain tld\n"
					returnhtml += checkdomainnameserver(domain)
					returnhtml += whoiscontent
					//fmt.Println(nserverre.FindAllString(whoiscontent, -1)) //-1表示返回所有匹配的值，[ar an al]
					log.Println(domain + " no whois server")
				}
			} else {
				returnhtml = checkdomainnameserver(domain)
				returnhtml += "hit from [" + globalwhoisserver + "]\n----------------------------------\n" + strings.Trim(whoiscontent, "\n")
			}
		}

	} else {
		returnhtml = "err get domain.ex:zhufan.net"
	}
	w.Header().Set("content-type", "text/html; charset=utf-8")
	w.Header().Set("X-Powered-By", "https://33.al")
	returnhtml = strings.ReplaceAll(returnhtml, "\n", "<br>")

	for _, ip := range whois_config.Ips {
		returnhtml = strings.ReplaceAll(returnhtml, ip, "8.8.8.8")
	}
	w.Write([]byte(returnhtml))
}
func main() {
	if _, err := toml.DecodeFile("config.toml", &whois_config); err != nil {
		log.Fatal(err)
	}
	fmt.Println(whois_config)
	whoisservers = map[string]string{}
	reg_whoisserver, _ := regexp.Compile(`\s(.{0,3}whois.*?(\s|\n))`)
	reg_httpwhoisserver, _ := regexp.Compile(`WEB (.*?(\s|\n))`)
	fi, err := os.Open("./tld_serv_list")
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}
	defer fi.Close()

	br := bufio.NewReader(fi)
	for {
		a, _, c := br.ReadLine()
		if c == io.EOF {
			break
		}
		whoisline := string(a) + "\n"
		if (strings.HasPrefix(whoisline, ".")) && !(strings.Contains(whoisline, "NONE")) && (len(whoisline) > 15) {
			domaintld := strings.TrimSpace(strings.Split(whoisline, "	")[0])
			line_reg := reg_whoisserver.FindAllString(whoisline, -1)
			if len(line_reg) > 0 {
				whoisservers[domaintld] = strings.TrimSpace(line_reg[0])
				domaintlds = append(domaintlds, domaintld)
			}
			line_reg_http := reg_httpwhoisserver.FindAllString(whoisline, -1)
			if len(line_reg_http) > 0 {
				whoisservers[domaintld] = strings.TrimSpace(line_reg_http[0][4:])
				domaintlds = append(domaintlds, domaintld)
			}
		}
	}
	fi, err = os.Open("./new_gtlds_list")
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}
	defer fi.Close()

	br = bufio.NewReader(fi)
	for {
		a, _, c := br.ReadLine()
		if c == io.EOF {
			break
		}
		whoisline := string(a)
		if !strings.HasPrefix(whoisline, "#") && whoisline != "" {
			domaintld := "." + strings.TrimSpace(whoisline)
			whoisservers[domaintld] = "whois.nic" + domaintld
			domaintlds = append(domaintlds, domaintld)
		}
	}
	fs := http.FileServer(http.Dir("html"))
	mux := http.NewServeMux()
	mux.HandleFunc("/api/", requestHandler)
	mux.Handle("/", http.StripPrefix("/", fs))
	http.ListenAndServe(":"+whois_config.Port, mux)
	select {} // block foreve
}
