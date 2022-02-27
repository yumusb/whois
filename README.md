## whois 

Golang based whois query server.

### files

```shell
yumu@yumu-pc:/whois$ tree
.
├── README.md
├── config.toml # config file 
├── go.mod
├── go.sum
├── html # front template
│   ├── bootstrap.min.css
│   ├── domain.js
│   ├── index.html
│   └── starter-template.css
├── main.go # main 
└── tld_serv_list # refer https://github.com/rfc1036/whois/blob/next/tld_serv_list

1 directory, 10 files
```

### config

```toml
port = "8080" # Port to listen
front = "https://whois.ip.sy" # Validate valid frontend domain (http_origin)
ip = ["x.x.x.x","x.x.x.x"] # Replace the output of the local IP with 8.8.8.8. ex: https://whois.ip.sy/#pp.ua
```

### demo

https://whois.ip.sy/

### thanks

https://github.com/rfc1036/whois
https://getbootstrap.com/docs/5.1/examples/jumbotron/