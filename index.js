/**
 * Wood Plugin Module.
 * 登录验证
 * by jlego on 2018-11-30
 */
const request = require('request-promise');

module.exports = (app = {}, config = {}) => {
  let { Redis, Token, catchErr, error, Util } = WOOD;
  // ===================生成签名
  function getSignature(product_key, data) {
    let strArr = [],
      signature = '';
    for(let key of Object.keys(data)){
      if(key === 'product_key') continue;
      let item = data[key];
      if(typeof item === 'object'){
        if(Array.isArray(item)){
          strArr.push(`${key}=${JSON.stringify(item.sort())}`);
        }else{
          let newObj = {};
          for(let subKey of Object.keys(item).sort()){
            newObj[subKey] = item[subKey];
          }
          strArr.push(`${key}=${JSON.stringify(newObj)}`);
        }
      }else{
        strArr.push(`${key}=${item}`);
      }
    }
    strArr.push(`product_key=${product_key}`);
    signature = Util.md5(strArr.sort().join(''));
    data.signature = signature;
    return data;
  }

  // ===================取接入信息
  async function getAppaccess(product_id){
    let appaccessResult = await new Redis('appaccess').getValue(product_id);
    let appaccess = JSON.parse(appaccessResult) || {};
    if (!appaccess.product_key) {
      console.error('appaccess请求失败');
      throw error('请求失败');
    }
    return appaccess;
  }

  app.Authenticate = {
    getAppaccess,
    getSignature,
    // ===================注册/登录帐号
    async loginOrReg(params) {
      let { signature, ...data } = params,
        {
          reg_from,
          product_id,
          product_key,
          openid,
          unionid,
          phone,
          email,
          name,
          password,
          userinfo,
          account_type,
          timestamp
        } = data,
        isOpenClient = ['wechat', 'qq', 'aliapp', 'weibo'].includes(reg_from);
      // 判断验证码

      // 检查应用接入
      if(!product_key){
        let appaccessResult = await getAppaccess(product_id);
        product_key = appaccessResult.product_key;
      }
      // 验证数据格式
      let hasErr = '', regData = {}; 
      if (isOpenClient) {
        if (!openid) {
          hasErr = '注册参数不正确';
        }else{
          regData.openid = openid;
        }
        // 判断签名
        let newData = getSignature(product_key, data);
        if(newData.signature !== signature) {
          console.error('signature请求失败');
          return error('请求失败');
        }
      } else {
        if (reg_from === 'phone') {
          if(!phone){
            hasErr = '手机号不能为空';
          }else{
            regData.phone = phone;
          }
        } else if (reg_from === 'email') {
          if(!email){
            hasErr = '邮箱不能为空';
          }else{
            regData.email = email;
          }
        } else {
          if(!name){
            hasErr = '用户名不能为空';
          }else{
            regData.name = name;
          }
        }
        if (!password) {
          hasErr = '密码不能为空';
        }else{
          regData.password = Util.md5(`${Util.md5(password)}.${product_key}`);
        }
      }
      if (hasErr) return error(hasErr);
      // 判断是否已注册
      let account_id = '',
        uid = 0,
        accountModel = WOOD.Model('account'),
        accountResult = await accountModel.findOne(regData);
      // 新注册
      if(Util.isEmpty(accountResult) || !accountResult){
        uid = await accountModel.db.rowid('account');
        regData.uid = uid;
        regData.reg_from = reg_from;
        regData.account_type = account_type;
        regData.unionid = unionid;
        Object.assign(regData, userinfo || {});
        let saveResult = await WOOD.Model('account').create(regData);
        account_id = saveResult._id;
      }else{
        if(!accountResult.status) throw error('此用户已被禁用');
        uid = accountResult.uid;
        account_id = accountResult._id;
      }   
      // 生成token, 24小时
      let token = new Token({expire: app.config.session_expire, secret: product_key}).createToken({ account_id, product_id });
      // console.warn('1111111111111111111111:', token);
      // 保存会话
      let sessionRedis = new Redis('session'),
        sessionKey = `${account_id}:${product_id}`,
        sessionData = {
          token,
          account_id,
          product_id,
          uid,
          ...userinfo
        };
      let sessionSave = await sessionRedis.setValue(sessionKey, JSON.stringify(sessionData), app.config.session_expire);
      return sessionData;
    },

    // ===================退出登录
    async signOut(userInfo = {}) {
      let sessionRedis = new Redis('session');
      let key = userInfo.product_id ? `${userInfo.account_id}:${userInfo.product_id}` : userInfo.account_id;
      let result = await sessionRedis.delKey(key);
      return true;
    },

    // ===================登录验证
    async verify(req, res, next){
      let theToken = req.headers.token || (req.method === 'GET' ? req.query.token : ''),
        decArr = theToken.split("."),
        product_key = '';
      if(decArr.length < 2){
        res.print(error('token不正确'));
        return;
      }else{
        try{
          let tokenData = JSON.parse(Buffer.from(decArr[0], "base64").toString("utf8"));
          let appaccessRedis = new Redis('appaccess', config.redis || 'master');
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
          let sessionRedis = new Redis('session');
          let key = userData.product_id ? `${userData.account_id}:${userData.product_id}` : userData.account_id;
          let cacheTokenResult = await catchErr(sessionRedis.getValue(key)),
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
            req.account = cacheToken;
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
    }
  };
  if(app.addAppProp) app.addAppProp('Authenticate', app.Authenticate);
  return app;
}