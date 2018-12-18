/**
 * Wood Plugin Module.
 * 登录验证
 * by jlego on 2018-11-30
 */
const { Token } = require('wood-token')();

module.exports = (app = {}, config = {idName: 'account_id'}) => {
  let { catchErr, error } = app;
  let RedisPlugin = app.Plugin('redis');
  if(RedisPlugin){
    app.Authenticate = async function(req, res, next){
      let theToken = req.headers.token || (req.method === 'GET' ? req.query.token : ''),
        decArr = theToken.split("."),
        product_key = '';
      if(decArr.length < 2){
        res.print(error('token不正确'));
        return;
      }else{
        try{
          let tokenData = JSON.parse(Buffer.from(decArr[0], "base64").toString("utf8"));
          let appaccessRedis = new RedisPlugin.Redis('appaccess', config.redis || 'master');
          let appaccessResult = await catchErr(appaccessRedis.getValue(tokenData.data.product_id));
          if (appaccessResult.err) {
            res.print(appaccessResult);
            return;
          }
          let appaccess = JSON.parse(appaccessResult.data) || {};
          product_key = appaccess.product_key;
          if (!product_key) {
            console.error('appaccess请求失败', tokenData.data.product_id);
            res.print(error('未找到此应用'));
            return;
          }
        }catch(err){
          res.print(error(err));
          return;
        }
      }
      if(theToken){
        let userData = new Token({expire: app.config.session_expire, secret: product_key}).checkToken(theToken);
        if(userData){
          let Redis = new RedisPlugin.Redis('session');
          let key = userData.product_id ? `${userData.account_id}:${userData.product_id}` : userData.account_id;
          let cacheTokenResult = await catchErr(Redis.getValue(key)),
            cacheToken = {};
          if (cacheTokenResult.err) {
            res.print(cacheTokenResult);
            return;
          }
          try{
            cacheToken = JSON.parse(cacheTokenResult.data) || {};
          }catch(err){
            res.print(error(err));
            return;
          }
          if(theToken === cacheToken.token){
            req.User = cacheToken;
            next();
          }else{
            res.print(error('未登录'));
          }
        }else{
          res.print(error('token过期或不正确'));
        }
      }else{
        res.print(error('token参数不能为空'));
      }
    };
    if(app.addAppProp) app.addAppProp('Authenticate', app.Authenticate);
  }else{
    console.warn('Not find redis in authenticate plugin');
  }
  return app;
}