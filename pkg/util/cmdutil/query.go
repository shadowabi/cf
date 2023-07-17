package cmdutil

import (
	log "github.com/sirupsen/logrus"
	"github.com/teamssix/cf/pkg/util/cmdutil/identify"
	"github.com/teamssix/cf/pkg/util/pubutil"
	"regexp"
	"strings"
)

func IdentifyProvider(AccessKeyId, SecretAccessKeyId, SessionToken string) pubutil.Provider {
	log.Debugf("\nAccessKeyId: %s\nSecretAccessKeyId: %s\nSessionToken: %s", AccessKeyId, SecretAccessKeyId, SessionToken)
	var provider pubutil.Provider
	switch {
	case (regexp.MustCompile("^LTAI[0-9a-zA-Z]{20}$").MatchString(AccessKeyId) || strings.HasPrefix(AccessKeyId, "STS")):
		// 正则已验证完全正确
		if SecretAccessKeyId == "" || identify.AlibabaIdentity(AccessKeyId, SecretAccessKeyId, SessionToken) {
			provider.CN = "阿里云"
			provider.EN = "Alibaba Cloud"
		}
	case regexp.MustCompile("^AKID[0-9a-zA-Z]{32}$").MatchString(AccessKeyId):
		// 正则已验证完全正确
		if SecretAccessKeyId == "" || identify.TencentIdentity(AccessKeyId, SecretAccessKeyId, SessionToken) {
			provider.CN = "腾讯云"
			provider.EN = "Tencent Cloud"
		}
	case regexp.MustCompile("(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}").MatchString(AccessKeyId):
		// 正则源自 RExpository
		if SecretAccessKeyId == "" || identify.AwsIdentity(AccessKeyId, SecretAccessKeyId, SessionToken) {
			provider.CN = "亚马逊"
			provider.EN = "AWS"
		}
	case regexp.MustCompile("^ALTAK[0-9a-zA-Z]{21}$").MatchString(AccessKeyId):
		// 正则已验证完全正确
		if SecretAccessKeyId == "" || identify.BaiduIdentity(AccessKeyId, SecretAccessKeyId, SessionToken) {
			provider.CN = "百度云"
			provider.EN = "Baidu Cloud"
		}
	case (strings.HasPrefix(AccessKeyId, "AKL") || strings.HasPrefix(AccessKeyId, "AKTP")):
		if SecretAccessKeyId == "" || identify.HuoshanIdentity(AccessKeyId, SecretAccessKeyId) {
			provider.CN = "火山引擎"
			provider.EN = "Volcano Engine"
		}
	case regexp.MustCompile("^AKLT[\\w-]{20}$").MatchString(AccessKeyId) || regexp.MustCompile("^KS3[A-Za-z0-9]{10,40}$").MatchString(AccessKeyId):
		// 正则已验证完全正确，KS3规则来自曾哥文章
		provider.CN = "金山云"
		provider.EN = "Kingsoft Cloud"
	case regexp.MustCompile("^JDC_[0-9A-Z]{28}$").MatchString(AccessKeyId):
		// 正则已验证完全正确
		provider.CN = "京东云"
		provider.EN = "JD Cloud"
	case regexp.MustCompile("AIza[0-9A-Za-z_\\-]{35}").MatchString(AccessKeyId) || regexp.MustCompile("^GOOG[\\w\\W]{10,30}$").MatchString(AccessKeyId):
		// 正则源自 RExpository, GOOG规则来自曾哥文章
		provider.CN = "谷歌云"
		provider.EN = "GCP"
	case (regexp.MustCompile("^[A-Z0-9]*$").MatchString(AccessKeyId) && (len(AccessKeyId) == 20 || len(AccessKeyId) == 40)):
		// 正则已验证完全正确
		if SecretAccessKeyId == "" || identify.HuaweiIdentity(AccessKeyId, SecretAccessKeyId, SessionToken) {
			provider.CN = "华为云"
			provider.EN = "Huawei Cloud"
		}
	case (regexp.MustCompile(`^[a-zA-Z0-9-_]{40}$`).MatchString(AccessKeyId)):
		if SecretAccessKeyId == "" || identify.QiniuIdentity(AccessKeyId, SecretAccessKeyId) {
			provider.CN = "七牛云"
			provider.EN = "Qiniu Cloud"
		}
	//下面规则均来自曾哥文章，未进行验证
	case regexp.MustCompile("^UC[A-Za-z0-9]{10,40}$").MatchString(AccessKeyId):
		provider.CN = "优刻得"
		provider.EN = "UCloud"
	case regexp.MustCompile("^AZ[A-Za-z0-9]{34,40}$").MatchString(AccessKeyId):
		provider.CN = "微软云"
		provider.EN = "Microsoft Azure"
	case regexp.MustCompile("^IBM[A-Za-z0-9]{10,40}$").MatchString(AccessKeyId):
		provider.CN = "IBM云"
		provider.EN = "IBM Cloud"
	case regexp.MustCompile("^OCID[A-Za-z0-9]{10,40}$").MatchString(AccessKeyId):
		provider.CN = "Oracle云"
		provider.EN = "Oracle Cloud"
	case regexp.MustCompile("^QY[A-Za-z0-9]{10,40}$").MatchString(AccessKeyId):
		provider.CN = "青云"
		provider.EN = "QingCloud"
	case regexp.MustCompile("^LTC[A-Za-z0-9]{10,60}$").MatchString(AccessKeyId):
		provider.CN = "联通云"
		provider.EN = "China Unicom Cloud"
	case regexp.MustCompile("^LTC[A-Za-z0-9]{10,60}$").MatchString(AccessKeyId):
		provider.CN = "联通云"
		provider.EN = "China Unicom Cloud"
	case regexp.MustCompile("^YD[A-Za-z0-9]{10,60}$").MatchString(AccessKeyId):
		provider.CN = "移动云"
		provider.EN = "China Mobile Cloud"
	case regexp.MustCompile("^CTC[A-Za-z0-9]{10,60}$").MatchString(AccessKeyId):
		provider.CN = "电信云"
		provider.EN = "China Telecom Cloud"
	case regexp.MustCompile("^YYT[A-Za-z0-9]{10,60}$").MatchString(AccessKeyId):
		provider.CN = "一云通"
		provider.EN = "Yonyou Cloud"
	case regexp.MustCompile("^YY[A-Za-z0-9]{10,40}$").MatchString(AccessKeyId):
		provider.CN = "用友云"
		provider.EN = "Yonyou Cloud"
	case regexp.MustCompile("^CI[A-Za-z0-9]{10,40}$").MatchString(AccessKeyId):
		provider.CN = "南大通用云"
		provider.EN = "OUCDC"
	case regexp.MustCompile("^gcore[A-Za-z0-9]{10,30}$").MatchString(AccessKeyId):
		provider.CN = "G-Core Labs"
		provider.EN = "G-Core Labs"			
	default:
		provider.CN = ""
		provider.EN = ""
	}
	return provider
}
