package grab

import (
	"bytes"
	"context"
	"fmt"
	"github.com/PuerkitoBio/goquery"
	"github.com/imroc/req/v3"
	"github.com/kataras/golog"
	"strconv"
	"strings"
)

type A360Crawler struct {
	client    *req.Client
	log       *golog.Logger
	searchUrl string
	detailUrl string
}

type RData struct {
	AddTime       int    `json:"add_time"`
	AddTimeStr    string `json:"add_time_str"`
	Description   string `json:"description"`
	ID            string `json:"id"`
	Tag           int    `json:"tag"`
	Title         string `json:"title"`
	UpdateTime    int    `json:"update_time"`
	UpdateTimeStr string `json:"update_time_str"`
}

type a360ListResp struct {
	Data         []RData `json:"data"`
	Length       int     `json:"length"`
	Pages        float64 `json:"pages"`
	RecordsTotal int     `json:"recordsTotal"`
	Start        int     `json:"start"`
}

func (a A360Crawler) ProviderInfo() *Provider {
	return &Provider{
		Name:        "360-cert",
		DisplayName: "360网络安全响应中心",
		Link:        "https://cert.360.cn/warning",
	}
}

func (a A360Crawler) GetPageCount(ctx context.Context, size int) (int, error) {
	var body a360ListResp
	_, err := a.client.R().AddQueryParam("start", "0").
		AddQueryParam("length", "6").
		SetContext(ctx).
		AddRetryCondition(func(resp *req.Response, err error) bool {
			if resp == nil {
				return true
			}
			if err = resp.UnmarshalJson(&body); err != nil {
				a.log.Warnf("unmarshal json error, %s", err)
				return true
			}

			if body.RecordsTotal <= 0 {
				a.log.Warnf("invalid total size %d", body.RecordsTotal)
				return true
			}
			return false
		}).Get(a.searchUrl)
	if err != nil {
		return 0, err
	}

	total := body.RecordsTotal
	if total <= 0 {
		return 0, fmt.Errorf("invalid size %d", total)
	}
	pageCount := total / 6
	if pageCount == 0 {
		return 1, nil
	}
	if total%pageCount != 0 {
		pageCount += 1
	}
	return pageCount, nil
}

func (a A360Crawler) ParsePage(ctx context.Context, page int, size int) (chan *VulnInfo, error) {
	start := (page - 1) * 6
	a.log.Infof("parsing page %d", page)
	resp, err := a.client.R().
		SetContext(ctx).
		AddQueryParam("start", strconv.Itoa(start)).
		AddQueryParam("length", "6").
		Get(a.searchUrl)
	if err != nil {
		return nil, err
	}
	var body a360ListResp
	if err = resp.UnmarshalJson(&body); err != nil {
		return nil, err
	}
	a.log.Infof("page %d contains %d vulns", page, len(body.Data))
	results := make(chan *VulnInfo, 1)
	go func() {
		defer close(results)
		for _, data := range body.Data {
			select {
			case <-ctx.Done():
				return
			default:
			}

			avdInfo, err := a.parseSingle(ctx, data)
			if err != nil {
				a.log.Errorf("%s %s", err, data.ID)
				return
			}
			results <- avdInfo
		}
	}()
	return results, nil
}

func (a A360Crawler) IsValuable(info *VulnInfo) bool {
	return info.Severity == High || info.Severity == Critical
}

func (a A360Crawler) parseSingle(ctx context.Context, data RData) (*VulnInfo, error) {
	a.log.Debugf("parsing vuln %s", data.ID)
	resp, err := a.client.R().SetContext(ctx).AddQueryParam("id", data.ID).Get(a.detailUrl)
	if err != nil {
		return nil, err
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(resp.Bytes()))
	if err != nil {
		return nil, err
	}

	severity := doc.Find("body > div.main-container > div > div > div.main-content-news.col-md-8.col-sm-12.col-xs-12 > div.news-content > div > div.news-conent > table:nth-child(12) > tbody > tr:nth-child(2) > td:nth-child(2)").Text()
	severity = strings.TrimSpace(severity)
	level := Low
	switch severity {
	case "低危":
		level = Low
	case "中危":
		level = Medium
	case "高危":
		level = High
	case "严重":
		level = Critical
	}

	vulInfo := &VulnInfo{
		UniqueKey:   data.ID,
		Title:       data.Title,
		Severity:    level,
		From:        fmt.Sprintf("%s?id=%s", a.detailUrl, data.ID),
		Disclosure:  data.AddTimeStr,
		Description: data.Description,
		Creator:     a,
	}
	if strings.Contains(data.Title, "CVE-") {
		vulInfo.CVE = strings.Split(data.Title, ":")[0]
	}
	//a.log.Infof("found vuln %v", vulInfo)
	return vulInfo, nil
}

func NewA360Crawler() Grabber {
	client := NewHttpClient()
	//client.SetProxyURL("http://127.0.0.1:8080")
	return &A360Crawler{
		client:    client,
		log:       golog.Child("[360-cert]"),
		searchUrl: `https://cert.360.cn/warning/searchbypage`,
		detailUrl: `https://cert.360.cn/warning/detail`,
	}
}
