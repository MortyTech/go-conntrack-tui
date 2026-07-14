package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"
)

var tcpStates = map[uint8]string{
	0: "NONE", 1: "SYN_SENT", 2: "SYN_RECV", 3: "ESTABLISHED",
	4: "FIN_WAIT", 5: "CLOSE_WAIT", 6: "LAST_ACK", 7: "TIME_WAIT",
	8: "CLOSE", 9: "LISTEN",
}

type TargetMatcher struct {
	ips     []netip.Addr
	subnets []netip.Prefix
}

var activeFlows sync.Map

type TrackedConnection struct {
	MatchedIPs []string
	State      string
}

func main() {
	targetsFlag := flag.String("targets", "", "Comma-separated target IPs or subnets")
	flag.Parse()

	if *targetsFlag == "" {
		log.Fatal("Error: --targets flag is required.")
	}

	matcher, err := parseTargets(*targetsFlag)
	if err != nil {
		log.Fatalf("Failed to parse targets: %v", err)
	}

	c, err := conntrack.Dial(nil)
	if err != nil {
		log.Fatalf("Failed to open Netlink conntrack socket: %v", err)
	}
	defer c.Close()

	initialFlows, err := c.Dump(&conntrack.DumpOptions{})
	if err != nil {
		log.Fatalf("Failed to dump baseline: %v", err)
	}
	for _, flow := range initialFlows {
		processFlowUpdate(flow, matcher, false)
	}

	app := tview.NewApplication()
	table := tview.NewTable().
		SetBorders(true).
		SetFixed(1, 0).             
		SetSelectable(true, false). 
		SetEvaluateAllRows(true)    

	// Low-contrast selection block prevents text elements from shifting to unreadable black counters
	table.SetSelectedStyle(tcell.StyleDefault.
		Background(tcell.ColorDarkSlateGray).
		Foreground(tcell.ColorWhite))

	table.SetTitle(" Real-Time Network Conntrack Monitor (Sorted by TOTAL) ").SetTitleAlign(tview.AlignLeft)

	// Global shortcut handling to exit cleanly on 'q' or 'Q'
	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Rune() == 'q' || event.Rune() == 'Q' {
			app.Stop()
			return nil
		}
		return event
	})

	evCh := make(chan conntrack.Event, 8192)
	errChan, err := c.Listen(evCh, 4, netfilter.GroupsCT)
	if err != nil {
		log.Fatalf("Failed to establish event listener: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go runUIUpdater(ctx, app, table)
	go consumeEvents(ctx, evCh, errChan, matcher)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
		app.Stop()
	}()

	if err := app.SetRoot(table, true).Run(); err != nil {
		log.Fatalf("Error running TUI application: %v", err)
	}
}

func consumeEvents(ctx context.Context, evCh chan conntrack.Event, errChan chan error, matcher TargetMatcher) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-evCh:
			if event.Flow == nil {
				continue
			}
			switch event.Type {
			case conntrack.EventNew, conntrack.EventUpdate:
				processFlowUpdate(*event.Flow, matcher, false)
			case conntrack.EventDestroy:
				processFlowUpdate(*event.Flow, matcher, true)
			}
		case err := <-errChan:
			if err != nil {
				log.Printf("Netlink Event Stream Error: %v", err)
			}
			return
		}
	}
}

func processFlowUpdate(flow conntrack.Flow, matcher TargetMatcher, isDestroy bool) {
	if isDestroy {
		activeFlows.Delete(flow.ID)
		return
	}

	matchedIPs := matcher.getMatchedIPs(flow)
	if len(matchedIPs) == 0 {
		return
	}

	stateName := getFlowStateName(flow)
	
	var ips []string
	for _, ipAddr := range matchedIPs {
		ips = append(ips, ipAddr.String())
	}

	activeFlows.Store(flow.ID, &TrackedConnection{
		MatchedIPs: ips,
		State:      stateName,
	})
}

func runUIUpdater(ctx context.Context, app *tview.Application, table *tview.Table) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			activeStatesSet := make(map[string]bool)
			activeIPsSet := make(map[string]bool)

			activeFlows.Range(func(key, val interface{}) bool {
				conn := val.(*TrackedConnection)
				if conn.State != "TOTAL" && conn.State != "" {
					activeStatesSet[conn.State] = true
				}
				for _, ip := range conn.MatchedIPs {
					activeIPsSet[ip] = true
				}
				return true
			})

			var activeStates []string
			for state := range activeStatesSet {
				activeStates = append(activeStates, state)
			}
			sort.Strings(activeStates)

			matrix := make(map[string]map[string]int)
			for ip := range activeIPsSet {
				matrix[ip] = make(map[string]int)
				matrix[ip]["TOTAL"] = 0
				for _, state := range activeStates {
					matrix[ip][state] = 0
				}
			}

			activeFlows.Range(func(key, val interface{}) bool {
				conn := val.(*TrackedConnection)
				for _, ip := range conn.MatchedIPs {
					if row, ipExists := matrix[ip]; ipExists {
						if _, stateExists := row[conn.State]; stateExists {
							matrix[ip][conn.State]++
						}
						matrix[ip]["TOTAL"]++
					}
				}
				return true
			})

			var sortedIPs []string
			for ip, stats := range matrix {
				if stats["TOTAL"] > 0 {
					sortedIPs = append(sortedIPs, ip)
				}
			}

			sort.Slice(sortedIPs, func(i, j int) bool {
				totalI := matrix[sortedIPs[i]]["TOTAL"]
				totalJ := matrix[sortedIPs[j]]["TOTAL"]
				if totalI != totalJ {
					return totalI > totalJ
				}
				return sortedIPs[i] < sortedIPs[j]
			})

			app.QueueUpdateDraw(func() {
				selectedRow, selectedCol := table.GetSelection()
				table.Clear()

				// Headers Row
				table.SetCell(0, 0, tview.NewTableCell("Target IP").SetTextColor(tcell.ColorYellow).SetSelectable(false))
				colIndex := 1
				for _, state := range activeStates {
					table.SetCell(0, colIndex, tview.NewTableCell(state).SetTextColor(tcell.ColorYellow).SetSelectable(false))
					colIndex++
				}
				table.SetCell(0, colIndex, tview.NewTableCell("TOTAL").SetTextColor(tcell.GetColor("cyan")).SetSelectable(false))

				// Data Rows
				for rowIndex, ip := range sortedIPs {
					displayRow := rowIndex + 1
					stats := matrix[ip]

					// Target IP - Clean White Text
					table.SetCell(displayRow, 0, tview.NewTableCell(ip).SetTextColor(tcell.ColorWhite))

					// Metrics Columns - Vibrant Green Text
					cIdx := 1
					for _, state := range activeStates {
						val := stats[state]
						table.SetCell(displayRow, cIdx, tview.NewTableCell(fmt.Sprintf("%d", val)).SetTextColor(tcell.ColorGreen))
						cIdx++
					}

					// Total Column - High-readability Cyan Text
					table.SetCell(displayRow, cIdx, tview.NewTableCell(fmt.Sprintf("%d", stats["TOTAL"])).SetTextColor(tcell.GetColor("cyan")))
				}

				if selectedRow >= table.GetRowCount() {
					selectedRow = table.GetRowCount() - 1
				}
				if selectedRow < 1 && table.GetRowCount() > 1 {
					selectedRow = 1
				}
				table.Select(selectedRow, selectedCol)
			})
		}
	}
}

func parseTargets(input string) (TargetMatcher, error) {
	var matcher TargetMatcher
	for _, token := range strings.Split(input, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if strings.Contains(token, "/") {
			prefix, err := netip.ParsePrefix(token)
			if err != nil {
				return matcher, err
			}
			matcher.subnets = append(matcher.subnets, prefix)
		} else {
			addr, err := netip.ParseAddr(token)
			if err != nil {
				return matcher, err
			}
			matcher.ips = append(matcher.ips, addr)
		}
	}
	return matcher, nil
}

func (tm *TargetMatcher) getMatchedIPs(flow conntrack.Flow) []netip.Addr {
	endpoints := []netip.Addr{
		flow.TupleOrig.IP.SourceAddress, flow.TupleOrig.IP.DestinationAddress,
		flow.TupleReply.IP.SourceAddress, flow.TupleReply.IP.DestinationAddress,
	}
	seen := make(map[netip.Addr]bool)
	var matches []netip.Addr

	for _, ep := range endpoints {
		if !ep.IsValid() || seen[ep] {
			continue
		}
		for _, targetIP := range tm.ips {
			if ep == targetIP {
				seen[ep] = true
				matches = append(matches, ep)
				break
			}
		}
		if !seen[ep] {
			for _, subnet := range tm.subnets {
				if subnet.Contains(ep) {
					seen[ep] = true
					matches = append(matches, ep)
					break
				}
			}
		}
	}
	return matches
}

func getFlowStateName(flow conntrack.Flow) string {
	if flow.ProtoInfo.TCP != nil {
		if name, ok := tcpStates[flow.ProtoInfo.TCP.State]; ok {
			return name
		}
		return "TCP_UNKNOWN"
	}
	switch flow.TupleOrig.Proto.Protocol {
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	default:
		return fmt.Sprintf("PROTO_%d", flow.TupleOrig.Proto.Protocol)
	}
}
