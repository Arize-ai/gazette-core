package mainboilerplate

import (
	"os"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

func TestTmpFSCollector(t *testing.T) {
	var path = os.TempDir()
	var total, free, avail, err = statFS(path)
	require.NoError(t, err)
	require.NotZero(t, total)
	require.LessOrEqual(t, free, total)
	require.LessOrEqual(t, avail, free)

	var collector = newTmpFSCollector(path)
	var registry = prometheus.NewPedanticRegistry()
	require.NoError(t, registry.Register(collector))

	var families, gatherErr = registry.Gather()
	require.NoError(t, gatherErr)

	var got = map[string]float64{}
	for _, family := range families {
		require.Equal(t, dto.MetricType_GAUGE, family.GetType())
		require.Len(t, family.Metric, 1)
		var metric = family.Metric[0]
		require.Equal(t, "path", metric.Label[0].GetName())
		require.Equal(t, path, metric.Label[0].GetValue())
		got[family.GetName()] = metric.GetGauge().GetValue()
	}

	require.Equal(t, map[string]float64{
		"gazette_tmpfs_size_bytes":  float64(total),
		"gazette_tmpfs_free_bytes":  float64(free),
		"gazette_tmpfs_avail_bytes": float64(avail),
	}, got)
}
