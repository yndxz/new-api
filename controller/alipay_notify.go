package controller

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/logger"
	"github.com/QuantumNous/new-api/model"

	"github.com/gin-gonic/gin"
	"github.com/shopspring/decimal"
)

// alipayPublicKey 支付宝公钥，部署时请替换为您的支付宝公钥
// 从支付宝开放平台 → 开发设置 → 支付宝公钥 获取（注意：不是应用公钥，是支付宝公钥）
const alipayPublicKey = `/mh3ViqRqxoMpIpbKaRvEyzmbO3ikTw6RTdwdx6XQUrN68FiSXEPafYGJtBslsm0s+ngGGy3eQQuBKMtPzqnn7mwduUMX9nNZc/vFlZ0gOb6XNrh5HmvXQUeDw96rLeT/2N8J71W6WdztFNRgYRR3DXFbnb4sfOtMDmMtOQbirEiy8PHYUsbmR1+nMAhjhg8DdKdp+tsEdooeHO5rcz+/wVZv7W4QAMbyZKcd8RqIkUUk9bbB8UMKwDm/BYoZgdH8l3oW/JO1j1ffirPaFN137d5KKRIUVBZuL+by4qU/2B0AMl/5a54kjJq6hDS9FLS8BtlpQIDAQAB`

// verifyAlipaySign 使用硬编码的支付宝公钥进行 RSA2 验签
func verifyAlipaySign(params map[string]string) (bool, error) {
	// 直接 Base64 解码公钥
	raw, err := base64.StdEncoding.DecodeString(alipayPublicKey)
	if err != nil {
		return false, fmt.Errorf("支付宝公钥 Base64 解码失败: %w", err)
	}

	pub, err := x509.ParsePKIXPublicKey(raw)
	if err != nil {
		pub, err = x509.ParsePKCS1PublicKey(raw)
		if err != nil {
			return false, fmt.Errorf("解析支付宝公钥失败: %w", err)
		}
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("支付宝公钥类型错误")
	}

	signStr := params["sign"]
	if signStr == "" {
		return false, fmt.Errorf("缺少 sign 参数")
	}
	sign, err := base64.StdEncoding.DecodeString(signStr)
	if err != nil {
		return false, fmt.Errorf("Base64 解码 sign 失败: %w", err)
	}

	var keys []string
	for k := range params {
		if k != "sign" && k != "sign_type" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	var parts []string
	for _, k := range keys {
		v := params[k]
		decoded, decErr := url.QueryUnescape(v)
		if decErr == nil {
			v = decoded
		}
		parts = append(parts, k+"="+v)
	}
	signContent := strings.Join(parts, "&")

	hashed := sha256.Sum256([]byte(signContent))
	if err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hashed[:], sign); err != nil {
		return false, fmt.Errorf("RSA2 验签失败: %w", err)
	}
	return true, nil
}

func AlipayNotify(c *gin.Context) {
	if c.Request.Method != "POST" {
		_, _ = c.Writer.Write([]byte("fail"))
		return
	}

	if err := c.Request.ParseForm(); err != nil {
		logger.LogError(c.Request.Context(), fmt.Sprintf("支付宝通知 表单解析失败 path=%q client_ip=%s error=%q", c.Request.RequestURI, c.ClientIP(), err.Error()))
		_, _ = c.Writer.Write([]byte("fail"))
		return
	}

	params := make(map[string]string, len(c.Request.Form))
	for k, v := range c.Request.Form {
		if len(v) > 0 {
			params[k] = v[0]
		}
	}

	if len(params) == 0 {
		logger.LogWarn(c.Request.Context(), fmt.Sprintf("支付宝通知 参数为空 path=%q client_ip=%s", c.Request.RequestURI, c.ClientIP()))
		_, _ = c.Writer.Write([]byte("fail"))
		return
	}

	logger.LogInfo(c.Request.Context(), fmt.Sprintf("支付宝通知 收到请求 path=%q client_ip=%s params=%q", c.Request.RequestURI, c.ClientIP(), common.GetJsonString(params)))

	// RSA2 验签（使用硬编码的公钥）
	verified, err := verifyAlipaySign(params)
	if !verified || err != nil {
		logger.LogWarn(c.Request.Context(), fmt.Sprintf("支付宝通知 验签失败 out_trade_no=%s error=%q client_ip=%s", params["out_trade_no"], err.Error(), c.ClientIP()))
		_, _ = c.Writer.Write([]byte("fail"))
		return
	}

	outTradeNo := params["out_trade_no"]
	logger.LogInfo(c.Request.Context(), fmt.Sprintf("支付宝通知 验签成功 out_trade_no=%s trade_no=%s trade_status=%s client_ip=%s", outTradeNo, params["trade_no"], params["trade_status"], c.ClientIP()))

	if params["trade_status"] != "TRADE_SUCCESS" && params["trade_status"] != "TRADE_FINISHED" {
		logger.LogInfo(c.Request.Context(), fmt.Sprintf("支付宝通知 忽略非成功状态 out_trade_no=%s trade_status=%s client_ip=%s", outTradeNo, params["trade_status"], c.ClientIP()))
		_, _ = c.Writer.Write([]byte("success"))
		return
	}

	LockOrder(outTradeNo)
	defer UnlockOrder(outTradeNo)

	topUp := model.GetTopUpByTradeNo(outTradeNo)
	if topUp == nil {
		logger.LogWarn(c.Request.Context(), fmt.Sprintf("支付宝通知 订单不存在 out_trade_no=%s client_ip=%s", outTradeNo, c.ClientIP()))
		_, _ = c.Writer.Write([]byte("fail"))
		return
	}

	if topUp.Status == common.TopUpStatusSuccess {
		logger.LogInfo(c.Request.Context(), fmt.Sprintf("支付宝通知 订单已处理（幂等） out_trade_no=%s client_ip=%s", outTradeNo, c.ClientIP()))
		_, _ = c.Writer.Write([]byte("success"))
		return
	}

	if topUp.Status != common.TopUpStatusPending {
		logger.LogWarn(c.Request.Context(), fmt.Sprintf("支付宝通知 订单状态异常 out_trade_no=%s status=%s client_ip=%s", outTradeNo, topUp.Status, c.ClientIP()))
		_, _ = c.Writer.Write([]byte("fail"))
		return
	}

	topUp.Status = common.TopUpStatusSuccess
	topUp.CompleteTime = common.GetTimestamp()
	topUp.PaymentMethod = "alipay"

	if err := topUp.Update(); err != nil {
		logger.LogError(c.Request.Context(), fmt.Sprintf("支付宝通知 更新订单失败 out_trade_no=%s user_id=%d error=%q", outTradeNo, topUp.UserId, err.Error()))
		_, _ = c.Writer.Write([]byte("fail"))
		return
	}

	dAmount := decimal.NewFromInt(topUp.Amount)
	dQuotaPerUnit := decimal.NewFromFloat(common.QuotaPerUnit)
	quotaToAdd := int(dAmount.Mul(dQuotaPerUnit).IntPart())
	if quotaToAdd <= 0 {
		logger.LogWarn(c.Request.Context(), fmt.Sprintf("支付宝通知 无效加额 out_trade_no=%s user_id=%d amount=%d", outTradeNo, topUp.UserId, topUp.Amount))
		_, _ = c.Writer.Write([]byte("success"))
		return
	}

	if err := model.IncreaseUserQuota(topUp.UserId, quotaToAdd, true); err != nil {
		logger.LogError(c.Request.Context(), fmt.Sprintf("支付宝通知 增加额度失败 out_trade_no=%s user_id=%d quota=%d error=%q", outTradeNo, topUp.UserId, quotaToAdd, err.Error()))
		_, _ = c.Writer.Write([]byte("fail"))
		return
	}

	logger.LogInfo(c.Request.Context(), fmt.Sprintf("支付宝通知 充值成功 out_trade_no=%s user_id=%d quota=%d money=%.2f", outTradeNo, topUp.UserId, quotaToAdd, topUp.Money))
	model.RecordTopupLog(topUp.UserId, fmt.Sprintf("使用支付宝充值成功，充值金额: %v，支付金额：%f", logger.LogQuota(quotaToAdd), topUp.Money), c.ClientIP(), "alipay", "alipay")

	_, _ = c.Writer.Write([]byte("success"))
}
