module.exports = function(RED) {
  var noble = require('@abandonware/noble');
  var crypto = require('crypto');
  var xor = require('buffer-xor')

  var PLEJD_SERVICE = "31ba000160854726be45040c957391b5"
  var DATA_UUID = "31ba000460854726be45040c957391b5"
  var LAST_DATA_UUID = "31ba000560854726be45040c957391b5"
  var AUTH_UUID = "31ba000960854726be45040c957391b5"
  var PING_UUID = "31ba000a60854726be45040c957391b5"

  function PlejdConnectionNode(n) {
    RED.nodes.createNode(this, n);

    var node = this;

    node.cryptoKey = n.cryptoKey;

    if (node.cryptoKey) {
      node.cryptoKey = Buffer.from(node.cryptoKey.replace(/-/g, ''), 'hex');
    } else {
      node.error('No cryptokey found!');
      return;
    }

    node.plejdService = null;
    node.dataCharacteristic = null;
    node.lastDataCharacteristic = null;
    node.authCharacteristic = null;
    node.pingCharacteristic = null;
    node.address = null;
    node.plejdPeripheral = null;
    node.powerOn = false;

    node.subscriptions = {};

    node.connect = function() {
      if (node.isConnecting || node.isConnected) {
        node.error('Already connecting');
        return;
      }

      node.debug('Start plejd connect');

      node.isConnecting = true;

      node.debug('Scanning... ' + noble.state);
      if (noble.state === 'poweredOn') {
        noble.startScanning([PLEJD_SERVICE], false);
        setTimeout(this.handleNotYetConnected, 5000);
      } else {
        noble.on('stateChange', function(state) {
          if (state === 'poweredOn') {
            noble.startScanning([PLEJD_SERVICE], false);
            setTimeout(this.handleNotYetConnected, 5000);
          }
        });
      }

      noble.on('discover', function(peripheral) {
        if (node.plejdPeripheral) {
          node.debug('Already got peripheral');
          noble.stopScanning();
          return;
        }

        node.debug('found peripheral: ' + peripheral.address);


        node.address = reverseBuffer(Buffer.from(String(peripheral.address).replace(/\:/g, ''), 'hex'));

        peripheral.connect(function(err) {
          if (err) {
            node.error(peripheral.address + " - Failed to connect to peripheral: " + err);
            return;
          }
          node.debug(peripheral.address + ' - Connected to peripheral');

          peripheral.discoverSomeServicesAndCharacteristics([PLEJD_SERVICE], [], function(err, services, characteristics) {
            if (err || !services) {
                node.isConnecting = false;
                node.error(peripheral.address + ' - No service found', err);
                return;
            }

            service = services[0];

            node.debug(peripheral.address + ' - found service: ' + service.uuid);

            var dataCharacteristic = null;
            var lastDataCharacteristic = null;
            var authCharacteristic = null;
            var pingCharacteristic = null;
            characteristics.forEach(function(characteristic) {
              if (DATA_UUID == characteristic.uuid) {
                dataCharacteristic = characteristic;
              } else if (LAST_DATA_UUID == characteristic.uuid) {
                lastDataCharacteristic = characteristic;
              } else if (AUTH_UUID == characteristic.uuid) {
                authCharacteristic = characteristic;
              } else if (PING_UUID == characteristic.uuid) {
                pingCharacteristic = characteristic;
              }
            });

            if (dataCharacteristic &&
                lastDataCharacteristic &&
                authCharacteristic &&
                pingCharacteristic) {

              node.authenticate(authCharacteristic, function() {
                node.plejdPing(pingCharacteristic, function(pingOk) {
                  if (pingOk === false) {
                    node.debug(peripheral.address + " - Initial ping failed, skipping peripheral");
                    peripheral.disconnect();
                    return;
                  }

                  if (node.plejdPeripheral) {
                    node.debug(peripheral.address + " - Already connected, skipping peripheral");
                    peripheral.disconnect();
                    return;
                  }


                  node.plejdPeripheral = peripheral;
                  node.plejdService = service;

                  node.isConnected = true;
                  node.isConnecting = false;
                  node.dataCharacteristic = dataCharacteristic;
                  node.lastDataCharacteristic = lastDataCharacteristic;
                  node.authCharacteristic = authCharacteristic;
                  node.pingCharacteristic = pingCharacteristic;

                  noble.stopScanning();

                  node.log(peripheral.address + ' - Plejd connected');

                  node.startPing();
                  node.startListening();
                });
              });

            } else {
              node.error(peripheral.address + ' - missing characteristics, skipping peripheral');
              peripheral.disconnect();
              return;
            }
          });
        });

        peripheral.once('disconnect', function() {
          node.debug(peripheral.address + ' - Peripheral disconnected');
          if (peripheral.address === node.plejdPeripheral.address) {
            node.disconnect(function() {
              node.connect();
            })
          }
        })
      });

    };

    this.handleNotYetConnected = function() {
      if (!node.isConnected) {
        node.info("Timeout trying to connect, restarting");
        noble.stopScanning();
        node.disconnect(function() {
          node.connect();
        });
      }
    }

    this.startListening = function() {
      node.lastDataCharacteristic.subscribe(function(err) {
        if (err) {
          node.error('subscribe ' + err);
          return;
        }

        node.lastDataCharacteristic.on('data', function(data, isNotification) {
          var dec = plejdEncDec(node.cryptoKey, node.address, data);

          var dim = 0xffff;
          var state = null;

          var id = parseInt(dec[0], 10);

          if (dec.toString('hex', 3, 5) === '00c8' || dec.toString('hex', 3, 5) === '0098') {
            state = parseInt(dec.toString('hex', 5, 6), 10);
            dim = parseInt(dec.toString('hex', 6, 8), 16) >> 8;
          } else if (dec.toString('hex', 3, 5) === '0097') {
            state = parseInt(dec.toString('hex', 5, 6), 10);
          } else {
            node.debug('Unknown command: ' + dec.toString('hex', 3, 5));
          }

          if (state == 0) {
            state = 'Off';
          } else {
            state = 'On';
          }

          node.debug('id: ' + id + ' state: ' + state + ' dim: ' + dim);

          for (var s in node.subscriptions) {
            if (node.subscriptions.hasOwnProperty(s)) {
              node.subscriptions[s]({id: id, state: state, dim: dim});
            }
          }
        });
      });
    };

    this.register = function(nodeId) {
      node.subscriptions[nodeId] = function() {};

      if (Object.keys(node.subscriptions).length === 1) {
        node.connect();
      }
    };

    this.unregister = function(nodeId, callback) {
      if (node.subscriptions.hasOwnProperty(nodeId)) {
        delete node.subscriptions[nodeId];
      }

      if (Object.keys(node.subscriptions).length === 0) {
        node.disconnect(callback);
      } else {
        if (callback) {
          callback();
        }
      }
    };

    this.subscribe = function(nodeId, callback) {
      node.debug('Subscribing: ' + nodeId);
      node.subscriptions[nodeId] = callback;
    };

    this.setState = function(id, state, dim) {
      if (state.toLowerCase() === 'on') {
        node.turnOn(id, dim);
      } else {
        node.turnOff(id);
      }
    };

    this.disconnect = function(callback) {
      node.log('Disconnecting');
      clearInterval(node.pingIndex);
      if (node.isConnected || node.isConnecting) {
        node.plejdPeripheral.disconnect(function(err) {
          node.log('Disconnected');
          if (err) {
            node.error(err);
          }
        });
      } else {
        node.log('Already disconnected');
      }
      node.isConnected = false;
      node.isConnecting = false;
      node.plejdService = null;
      node.dataCharacteristic = null;
      node.lastDataCharacteristic = null;
      node.authCharacteristic = null;
      node.pingCharacteristic = null;
      node.address = null;
      node.plejdPeripheral = null;
      if (callback) {
        callback();
      }
    };

    this.startPing = function() {
      clearInterval(node.pingIndex);
      node.debug("Starting ping");
      node.pingIndex = setInterval(function() {
        if (node.isConnected) {
          node.plejdPing(node.pingCharacteristic, function(pingOk) {
            if (pingOk === false) {
              node.disconnect(function() {
                node.debug("Reconnecting due to ping ping not ok");
                node.connect();
              });
            }
          });
        } else {
          node.disconnect(function() {
            node.debug("Reconnecting due to not connected during ping");
            node.connect();
          });
        }
      }, 1000 * 60 * 3);
    };

    this.plejdPing = function(pingCharacteristic, callback) {
      if (!pingCharacteristic) {
        node.error('No ping characteristic set');
        return callback(false);
      }

      var ping = crypto.randomBytes(1);

      pingCharacteristic.write(ping, false, function(err) {
        if (err) {
          node.error('Ping write failed: ' + err);
          return callback(false);
        }

        pingCharacteristic.read(function(err, pong) {
          if (err) {
            node.error('Ping read failed: ' + err);
            return callback(false);
          }

          if(((ping[0] + 1) & 0xff) !== pong[0]) {
            node.debug('False: No pong...' + ping[0] + ' ' + pong[0]);
            callback(false);
          } else {
            node.debug('True: Pong...' + ping[0] + ' ' + pong[0]);
            callback(true);
          }
        });
      });
    };

    function plejdChalresp(key, chal) {
      intermediate = crypto.createHash('sha256').update(xor(key, chal)).digest();

      var part1 = intermediate.subarray(0, 16);
      var part2 = intermediate.subarray(16);

      var resp = xor(part1, part2);

      return resp;
    }

    function plejdEncDec(key, addr, data) {
      var buf = Buffer.concat([addr, addr, addr.subarray(0, 4)]);

      var cipher = crypto.createCipheriv("aes-128-ecb", key, '')
      cipher.setAutoPadding(false)

      var ct = cipher.update(buf).toString('hex');
      ct += cipher.final().toString('hex');
      ct = Buffer.from(ct, 'hex');

      var output = "";
      for (var i = 0, length = data.length; i < length; i++) {
        output += String.fromCharCode(data[i] ^ ct[i % 16]);
      }

      node.debug(':: ' + Buffer.from(output, 'ascii').toString('hex'));

      return Buffer.from(output, 'ascii');
    }

    this.plejdWrite = function(handle, data, callback) {
      if (!handle) {
        return callback();
      }

      handle.write(data, false, function(err) {
        if (err) {
          node.error(err);
          return;
        }

        if (callback) {
          callback();
        }
      });
    }

    this.turnOn = function(id, brightness) {
      var payload;

      if (!brightness) {
        payload = Buffer.from((id).toString(16).padStart(2, '0') + '0110009701', 'hex');
      } else {
        brightness = brightness << 8 | brightness;
        payload = Buffer.from((id).toString(16).padStart(2, '0') + '0110009801' + (brightness).toString(16).padStart(4, '0'), 'hex');
      }

      node.plejdWrite(node.dataCharacteristic, plejdEncDec(node.cryptoKey, node.address, payload))
    }

    this.turnOff = function(id) {
      var payload = Buffer.from((id).toString(16).padStart(2, '0') + '0110009700', 'hex');
      node.plejdWrite(node.dataCharacteristic, plejdEncDec(node.cryptoKey, node.address, payload))
    }

    this.authenticate = function(authCharacteristic, callback) {
        authCharacteristic.write(Buffer.from([0]), false, function(err) {
          if (err) {
            node.error(err);
            return;
          }
          authCharacteristic.read(function(err, data) {
            if (err) {
              node.error(err);
              return;
            }

            resp = plejdChalresp(node.cryptoKey, data);

            authCharacteristic.write(resp, false, function(err) {
              if (err) {
                node.error(err);
                return;
              }

              callback();
            });
          });
        });
    }

    function reverseBuffer(src) {
      var buffer = Buffer.allocUnsafe(src.length)

      for (var i = 0, j = src.length - 1; i <= j; ++i, --j) {
        buffer[i] = src[j]
        buffer[j] = src[i]
      }

      return buffer
    }

  }
  RED.nodes.registerType("plejd", PlejdConnectionNode);

  function PlejdOutNode(config) {
    RED.nodes.createNode(this, config);

    this.plejdConnection = RED.nodes.getNode(config.plejd);
    var node = this;

    node.plejdConnection.register(node.id);
    node.on('input', function(msg) {
      var id = msg.payload.id,
          state = msg.payload.state || 'On',
          dim = msg.payload.dim || 255;

      node.plejdConnection.setState(id, state, dim);
    });

    node.on('close', function(done) {
      node.plejdConnection.unregister(node.id, done);
    });
  }
  RED.nodes.registerType("plejd out", PlejdOutNode);

  function PlejdInNode(config) {
    RED.nodes.createNode(this, config);

    this.plejdConnection = RED.nodes.getNode(config.plejd);

    var node = this;

    node.plejdConnection.register(node.id);
    node.plejdConnection.subscribe(node.id, function(data) {
      var msg = {};

      msg.payload = data;

      node.send(msg);
    });

    node.on('close', function(done) {
      node.plejdConnection.unregister(node.id, done);
    });
  }
  RED.nodes.registerType("plejd in", PlejdInNode);
}
