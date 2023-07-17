import log from 'book';
import Koa from 'koa';
import tldjs from 'tldjs';
import Debug from 'debug';
import http from 'http';
import { hri } from 'human-readable-ids';
import Router from 'koa-router';

import ClientManager from './lib/ClientManager';

const fs=require('fs-extra');
const nconf = require('nconf');

const configFileLocation="/etc/localtunnel-server/config";

const crypto = require('crypto');

function generateRandomBase32String(length) {
  const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let randomString = '';

  while (randomString.length < length) {
    const randomBytes = crypto.randomBytes(4);
    for (let i = 0; i < randomBytes.length && randomString.length < length; i++) {
      const index = randomBytes[i] % base32Chars.length;
      randomString += base32Chars[index];
    }
  }

  return randomString;
}

var defaultConfig={};
if(!fs.existsSync(configFileLocation)){
    console.log("not exist");
    defaultConfig={"secret":generateRandomBase32String(32),len:15,alg:"SHA-512",period:60}
	var getDirName = require('path').dirname;
    fs.mkdir(getDirName(configFileLocation), { recursive: true}, function (err) {
    	if(err) console.log(err);
	    fs.writeFileSync(configFileLocation,"{}");
	    nconf.file({file:configFileLocation});
	    nconf.set('totp:secret',defaultConfig.secret);
	    nconf.set('totp:len',defaultConfig.len);
	    nconf.set('totp:alg',defaultConfig.alg);
	    nconf.set('totp:period',defaultConfig.period);
	    nconf.save();
            console.log(defaultConfig);
	});
}

const debug = Debug('localtunnel:server');
const totp = require('totp-generator');



export default function(opt) {
    opt = opt || {};

    const validHosts = (opt.domain) ? [opt.domain] : undefined;
    const myTldjs = tldjs.fromUserSettings({ validHosts });
    const landingPage = opt.landing || 'https://localtunnel.github.io/www/';

    function GetClientIdFromHostname(hostname) {
        return myTldjs.getSubdomain(hostname);
    }

    const manager = new ClientManager(opt);

    const schema = opt.secure ? 'https' : 'http';

    const app = new Koa();
    const router = new Router();

    function mycallBack(ctx,res,next){
        console.log("yeah eya");
        next();
    }

    function allowedToCreateTunnel(ctx){
	nconf.file({file:configFileLocation});
	let clientToken = ctx.req.headers.token;
	let timestamp = ctx.req.headers.timestamp;
	let serverToken = totp(nconf.get('totp:secret'),{digits:nconf.get('totp:len'),algorithm:nconf.get('totp:alg'),period:nconf.get('totp:period')});
	if(serverToken===clientToken){
		return true
	}
	else{
		    return false
	}
    }


    router.get('/api/status', mycallBack ,async (ctx, next) => {
        const stats = manager.stats;
        ctx.body = {
            tunnels: stats.tunnels,
            mem: process.memoryUsage(),
        };
    });

    router.get('/api/tunnels/:id/status', async (ctx, next) => {
        const clientId = ctx.params.id;
        const client = manager.getClient(clientId);
        if (!client) {
            ctx.throw(404);
            return;
        }

        const stats = client.stats();
        ctx.body = {
            connected_sockets: stats.connectedSockets,
        };
    });

    app.use(router.routes());
    app.use(router.allowedMethods());

    // root endpoint
    app.use(async (ctx, next) => {
        const path = ctx.request.path;

        // skip anything not on the root path
        if (path !== '/') {
            await next();
            return;
        }

        const isNewClientRequest = ctx.query['new'] !== undefined;
        if (isNewClientRequest && allowedToCreateTunnel(ctx)) {
            const reqId = hri.random();
            debug('making new client with id %s', reqId);
            const info = await manager.newClient(reqId);

            const url = schema + '://' + info.id + '.' + ctx.request.host;
            info.url = url;
            ctx.body = info;
            return;
        }
	    else{
		return;
	}
        // no new client request, send to landing page
        ctx.redirect(landingPage);
    });

    // anything after the / path is a request for a specific client name
    // This is a backwards compat feature
    app.use(async (ctx, next) => {
        const parts = ctx.request.path.split('/');

        // any request with several layers of paths is not allowed
        // rejects /foo/bar
        // allow /foo
        if (parts.length !== 2) {
            await next();
            return;
        }

        const reqId = parts[1];

        // limit requested hostnames to 63 characters
        if (! /^(?:[a-z0-9][a-z0-9\-]{4,63}[a-z0-9]|[a-z0-9]{4,63})$/.test(reqId)) {
            const msg = 'Invalid subdomain. Subdomains must be lowercase and between 4 and 63 alphanumeric characters.';
            ctx.status = 403;
            ctx.body = {
                message: msg,
            };
            return;
        }

        debug('making new client with id %s', reqId);
        const info = await manager.newClient(reqId);

        const url = schema + '://' + info.id + '.' + ctx.request.host;
        info.url = url;
        ctx.body = info;
        return;
    });

    const server = http.createServer();

    const appCallback = app.callback();

    server.on('request', (req, res) => {
        // without a hostname, we won't know who the request is for
        const hostname = req.headers.host;
        if (!hostname) {
            res.statusCode = 400;
            res.end('Host header is required');
            return;
        }

        const clientId = GetClientIdFromHostname(hostname);
        if (!clientId) {
            appCallback(req, res);
            return;
        }

        const client = manager.getClient(clientId);
        if (!client) {
            res.statusCode = 404;
            res.end('404');
            return;
        }

        client.handleRequest(req, res);
    });

    server.on('upgrade', (req, socket, head) => {
        const hostname = req.headers.host;
        if (!hostname) {
            socket.destroy();
            return;
        }

        const clientId = GetClientIdFromHostname(hostname);
        if (!clientId) {
            socket.destroy();
            return;
        }

        const client = manager.getClient(clientId);
        if (!client) {
            socket.destroy();
            return;
        }

        client.handleUpgrade(req, socket);
    });

    return server;
};
