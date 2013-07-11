# deCAPTCHA - 智能验证码识别

deCAPTCHA 是一个异步的验证码识别API.

## 在其下, 目前实现了3个验证码识别模块

*  antigate/decaptcha 的人肉识别服务
*  利用IRC和XMPP上的好友进行识别
*  avlog.avplayer.org 提供的免费人肉识别服务 (服务器端利用antigate/decaptcha 的 *付费* 人肉识别服务为所有的avbot客户提供免费的验证码识别服务. 当然, 限制每个客户每天只能使用一次.)

## 未来的研究方向是下面这个识别算法

*  基于模式识别的智能识别算法

