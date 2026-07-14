# Real-time, event-driven connection visualizer for Linux  
Uses netlink conntrack event streams and a double-buffered TUI to track high-volume traffic targets and sort them instantly by connection density.


# Buil from source :
```bash
git clone https://github.com/MortyTech/go-conntrack-tui.git
cd go-conntrack-tui
go mod init goconntrack
go mod tidy
go build -o goconntrack .
```
# How to use it :
```bash
./goconntrack --help
Usage of ./goconntrack:
  -targets string
    	Comma-separated target IPs or subnets
```
```bash
./goconntrack --targets 172.26.0.0/14
```
```bash
./goconntrack --targets 1.1.1.1
```
```bash
./goconntrack --targets 9.9.9.9,1.1.1.1,172.16.0.0/16.10.0.0.0/8
```
