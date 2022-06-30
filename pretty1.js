var Convert = Convert || {};

Convert.base32toHex = function (data) {
	if (typeof(data) !== typeof("")) {
		throw new Error("Argument to base32toHex() is not a string");
	}
	if (data.length === 0) {
		throw new Error("Argument to base32toHex() is empty");
	}
	if (!data.match(/^[A-Z2-7]+=*$/i)) {
		throw new Error("Argument to base32toHex() contains invalid characters");
	}

	var ret = "";
	var map = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".split('');
	var segments = (data.toUpperCase() + "========").match(/.{1,8}/g);
	segments.pop();
	var strip = segments[segments.length - 1].match(/=*$/)[0].length;
	if (strip > 6) {
		throw new Error("Invalid base32 data (too much padding)");
	}
	for (var i = 0; i < segments.length; i++) {
		var buffer = 0;
		var chars = segments[i].split("");
		for (var j = 0; j < chars.length; j++) {
			buffer *= map.length;
			var index = map.indexOf(chars[j]);
			if (chars[j] === '=') {
				index = 0;
			}
			buffer += index;
		}
		var hex = ("0000000000" + buffer.toString(16)).substr(-10);
		ret += hex;
	}
	switch (strip) {
	case 6:
		return ret.substr(0, ret.length - 8);
	case 4:
		return ret.substr(0, ret.length - 6);
	case 3:
		return ret.substr(0, ret.length - 4);
	case 1:
		return ret.substr(0, ret.length - 2);
	default:
		return ret;
	}
};

Convert.hexToArray = function (hex) {
	return hex.match(/[\dA-Fa-f]{2}/g).map(function (v) {
		return parseInt(v, 16);
	});
};

Convert.arrayToHex = function (array) {
	var hex = "";
	if (array instanceof ArrayBuffer) {
		return Convert.arrayToHex(new Uint8Array(array));
	}
	for (var i = 0; i < array.length; i++) {
		hex += ("0" + array[i].toString(16)).substr(-2);
	}
	return hex;
};

Convert.int32toHex = function (i) {
	return ("00000000" + Math.floor(Math.abs(i)).toString(16)).substr(-8);
};

var TOTP = {
	getOtpCounter: function (time, interval) {
		return (time / interval) | 0;
	},

	getCurrentCounter: function (interval) {
		return TOTP.getOtpCounter(Date.now() / 1000 | 0, interval);
	},

	otp: function (keyHex, counterInt, size, cb) {
		var isInt = function (x) {
			return x === x | 0;
		};
		if (typeof(keyHex) !== typeof("")) {
			throw new Error("Invalid hex key");
		}
		if (typeof(counterInt) !== typeof(0) || !isInt(counterInt)) {
			throw new Error("Invalid counter value");
		}
		if (typeof(size) !== typeof(0) || (size < 6 || size > 10 || !isInt(size))) {
			throw new Error("Invalid size value (default is 6)");
		}

		TOTP.hmac(keyHex, "00000000" + Convert.int32toHex(counterInt), function (mac) {
			var offset = parseInt(mac.substr(-1), 16);
			var code = parseInt(mac.substr(offset * 2, 8), 16) & 0x7FFFFFFF;
			(cb || console.log)(("0000000000" + (code % Math.pow(10, size))).substr(-size));
		});
	},

	hmac: function (keyHex, valueHex, cb) {
		var algo = {
			name: "HMAC",
			hash: "SHA-1"
		};
		var modes = ["sign", "verify"];
		var key = Uint8Array.from(Convert.hexToArray(keyHex));
		var value = Uint8Array.from(Convert.hexToArray(valueHex));
		crypto.subtle.importKey("raw", key, algo, false, modes).then(function (cryptoKey) {
			crypto.subtle.sign(algo, cryptoKey, value).then(function (v) {
				(cb || console.log)(Convert.arrayToHex(v));
			});
		});
	},

	isCompatible: function () {
		var f = function (x) {
			return typeof(x) === typeof(f);
		};
		if (typeof(crypto) === typeof(TOTP) && typeof(Uint8Array) === typeof(f)) {
			return !!(crypto.subtle && f(crypto.subtle.importKey) && f(crypto.subtle.sign) && f(crypto.subtle.digest));
		}
		return false;
	}
}

if (typeof(Convert) !== typeof(TOTP)) {
	TOTP = null;	
	throw new Error("Modulo de seguridad no cargado correctamente");
}

