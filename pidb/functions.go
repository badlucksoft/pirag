package pidb

import(
		"fmt"
		"time"
	)

func BuildDate(month,tz string, day, year, hour, minute, second int) string {
	d := fmt.Sprintf("%s %02d %d %02d:%02d:%02d %s",month,day,year,hour,minute,second,tz)
	tm, err := time.Parse("Jan 02 2006 15:04:05 MST",d)
	gt := ""
	if err == nil {
	gmt := tm.In(time.UTC)
	gt = gmt.Format("2006-01-02 15:04:05 -0700")
    } else {
    fmt.Printf("timestamp parse error: %s\n",err)
    }
	return gt
}