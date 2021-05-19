const crypto = require('crypto');
const fetch = require('node-fetch');

const URL_API = 'https://api.tauros.io';
const URL_API_STAGING = 'https://api.staging.tauros.io';

class TaurosAPI {
  constructor(api_key, api_secret, staging=false) {
    this.url_api = !staging ? URL_API : URL_API_STAGING;
    this.api_key = api_key;
    this.api_secret = api_secret;
  }

  _nonce() {
    let nonce = Date.now() / 1000;
    return nonce.toString().replace(".", "");
  }

  _sign(data, nonce, method, path) {
    let body = data === null ? '{}' : JSON.stringify(data);

    let message = nonce + method.toUpperCase() + path + body;

    let api_sha256 = crypto.createHash('sha256').update(message).digest();

    // create a sha512 hmac with the secret
    let hmac = crypto.createHmac('sha512', Buffer.from(this.api_secret, 'base64'));

    let signature = hmac.update(api_sha256).digest('base64');

    return signature;
  }

  _privateRequest(path, method='GET', data=null, params=null) {
    if (this.api_key === null || this.api_secret === null) {
      return Promise.reject( {status_code: 401, message: 'Authentication credentials were not provided.'});
    }

    let url = new URL(this.url_api + path);
    if (method.toUpperCase() === 'GET' && params) {
      url.search = new URLSearchParams(params).toString();
    }
  
    const nonce = this._nonce();
    const signature = this._sign(data, nonce, method, path);
    const headers = {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + this.api_key,
      'Taur-Nonce': nonce,
      'Taur-Signature': signature
    }

    let request = {
        method: method,
        headers: headers,
    }

    if (data) request.body = JSON.stringify(data);

    return new Promise((resolve, reject) => {
      fetch(url, request)
      .then(res => res.ok ? res.json() : {status_code: res.status, message: res.statusText})
      .then(json => {
        resolve(json);
      })
      .catch(err => {
        reject(err.message);
      })
    })
  }

  _publicRequest(path, method='GET', data=null, params=null) {
    let url = new URL(this.url_api + path)
    if (method.toUpperCase() === 'GET' && params) {
      url.search = new URLSearchParams(params).toString()
    }
    const headers = {
      'Content-Type': 'application/json'
    }

    let request = {
      method: method, 
      headers: headers
    }

    if (data) request.body = JSON.stringify(data)

    return new Promise((resolve, reject) => {
      fetch(url, request)
      .then(res => res.ok ? res.json() : { status_code: res.status, message: res.statusText })
      .then(json => {
        resolve(json)
      })
      .catch(err => {
        reject(err.message)
      })
    })
  }

  get(path, params=null, is_public=false) {
    const method = 'GET';
    if (is_public) {
      return this._publicRequest(path, method, params=params);
    }
    return this._privateRequest(path, method, params=params);
  }

  post(path, data=null, is_public=false) {
    const method = 'POST';
    if (is_public) {
      return this._publicRequest(path, method, data);
    }
    return this._privateRequest(path, method, data);
  }

  put(path, data=null, is_public=false) {
    const method = 'PUT';
    if (is_public) {
      return this._publicRequest(path, method, data);
    }
    return this._privateRequest(path, method, data);
  }

  patch(path, data=null, is_public=false) {
    const method = 'PATCH';
    if (is_public) {
      return this._publicRequest(path, method, data);
    }
    return this._privateRequest(path, method, data);
  }

  delete(path, is_public=false) {
    const method = 'DELETE';
    if (is_public) {
      return this._publicRequest(path, method)
    }
    return this._privateRequest(path, method);
  }
}

module.exports = TaurosAPI;