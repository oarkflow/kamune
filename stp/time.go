package stp

import (
	"time"
)

var epoch = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).Unix()

func Now() Time {
	return Time(time.Now().Unix() - epoch)
}

type Time uint32

func (t Time) unix() time.Time {
	return time.Unix(int64(t)+epoch, 0).UTC()
}

func (t Time) String() string {
	return t.unix().Format("2006-01-02 15:04:05")
}

func (t Time) IsInPlusMinusSeconds(d int64) bool {
	now := int64(Now())
	return now+d > int64(t) && now-d < int64(t)
}
