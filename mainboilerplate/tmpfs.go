package mainboilerplate

import (
	"os"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

// tmpFSCollector reports capacity of the filesystem that backs os.TempDir()
// (typically /tmp). Values come from Statfs, so they include space held by
// open-but-unlinked files such as journal spools.
type tmpFSCollector struct {
	path  string
	size  *prometheus.Desc
	free  *prometheus.Desc
	avail *prometheus.Desc

	warnOnce sync.Once
}

func newTmpFSCollector(path string) *tmpFSCollector {
	var labels = prometheus.Labels{"path": path}
	return &tmpFSCollector{
		path: path,
		size: prometheus.NewDesc(
			"gazette_tmpfs_size_bytes",
			"Total size in bytes of the filesystem backing the process temporary directory.",
			nil, labels,
		),
		free: prometheus.NewDesc(
			"gazette_tmpfs_free_bytes",
			"Free bytes on the filesystem backing the process temporary directory, including reserved blocks.",
			nil, labels,
		),
		avail: prometheus.NewDesc(
			"gazette_tmpfs_avail_bytes",
			"Bytes available to non-privileged processes on the filesystem backing the process temporary directory.",
			nil, labels,
		),
	}
}

// Describe implements prometheus.Collector.
func (c *tmpFSCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.size
	ch <- c.free
	ch <- c.avail
}

// Collect implements prometheus.Collector.
func (c *tmpFSCollector) Collect(ch chan<- prometheus.Metric) {
	var total, free, avail, err = statFS(c.path)
	if err != nil {
		c.warnOnce.Do(func() {
			log.WithFields(log.Fields{"path": c.path, "err": err}).
				Warn("unable to collect temporary filesystem metrics")
		})
		return
	}

	ch <- prometheus.MustNewConstMetric(c.size, prometheus.GaugeValue, float64(total))
	ch <- prometheus.MustNewConstMetric(c.free, prometheus.GaugeValue, float64(free))
	ch <- prometheus.MustNewConstMetric(c.avail, prometheus.GaugeValue, float64(avail))
}

// RegisterTmpFSMetrics registers Prometheus gauges for the filesystem that
// backs os.TempDir(). Scrapes use Statfs so open-but-deleted spool files are
// counted against used capacity.
func RegisterTmpFSMetrics() {
	prometheus.MustRegister(newTmpFSCollector(os.TempDir()))
}
