# HiveMQ CE Hardening Notes (Final Campaign)

HiveMQ uses XML config files in `conf/config.xml` plus extension JARs.
There is no single .conf file equivalent. The hardening below maps
the Final-campaign findings to the right XML/extension control.

## Findings to mitigate

| Finding | Where to fix | Mechanism |
|---------|--------------|-----------|
| V1 Will injection | `conf/config.xml` `<security>` + extension | Allow-list ACL via extension SDK |
| V2 Retain poisoning | `<mqtt><retained-messages><enabled>` + extension | Restrict who can set retain |
| V3 ClientID hijack | `<security><allow-empty-client-id>false</allow-empty-client-id>` + auth extension | Authenticated client ID binding |
| V4 Wildcard `#` eavesdrop | extension SDK | Authorizer extension; deny `#` to non-admin |
| V11 Session resource | `<persistence><client-session>` ttl | Session expiry cap |
| V18 Oversized CONNECT | `<mqtt><packets><max-packet-size>` | 65536 bytes |
| V19 500 subs/SUBSCRIBE | `<mqtt><subscriptions><max-per-client>` | 20 |
| V20 PUBLISH flood | extension or fronting proxy | HiveMQ Enterprise has rate limiter |
| V53 UserProperty flood | `<mqtt><user-properties><max-user-properties>` | 16 |
| R3 keepalive | `<mqtt><keep-alive>` `<max-keep-alive>` | 60s, allow-unlimited=false |
| V52 SessionExpiry=∞ | `<mqtt><session-expiry><max-interval>` | 7200 |

## Sample config.xml fragment

```xml
<hivemq>
  <listeners>
    <tcp-listener>
      <port>1883</port>
      <enabled>false</enabled>
    </tcp-listener>
    <tls-tcp-listener>
      <port>8883</port>
      <bind-address>0.0.0.0</bind-address>
      <tls>
        <protocols>
          <protocol>TLSv1.3</protocol>
        </protocols>
        <client-authentication-mode>REQUIRED</client-authentication-mode>
        <keystore>
          <path>conf/server.jks</path>
        </keystore>
        <truststore>
          <path>conf/ca.jks</path>
        </truststore>
      </tls>
    </tls-tcp-listener>
  </listeners>

  <security>
    <allow-empty-client-id>false</allow-empty-client-id>
    <payload-format-validation>true</payload-format-validation>
    <utf8-validation>true</utf8-validation>
  </security>

  <mqtt>
    <packets>
      <max-packet-size>65536</max-packet-size>
    </packets>
    <subscriptions>
      <max-per-client>20</max-per-client>
    </subscriptions>
    <topic-alias>
      <max-per-client>8</max-per-client>
    </topic-alias>
    <user-properties>
      <max-user-properties>16</max-user-properties>
    </user-properties>
    <session-expiry>
      <max-interval>7200</max-interval>
    </session-expiry>
    <keep-alive>
      <allow-unlimited>false</allow-unlimited>
      <max-keep-alive>60</max-keep-alive>
    </keep-alive>
    <message-expiry>
      <max-interval>3600</max-interval>
    </message-expiry>
    <queued-messages>
      <max-queue-size>20</max-queue-size>
      <strategy>discard</strategy>
    </queued-messages>
    <quality-of-service>
      <max-qos>2</max-qos>
    </quality-of-service>
  </mqtt>

  <persistence>
    <mode>file</mode>
  </persistence>

  <restrictions>
    <max-connections>100</max-connections>
    <max-client-id-length>64</max-client-id-length>
  </restrictions>
</hivemq>
```

## Required extensions

1. **hivemq-file-rbac-extension** (open source): topic-level ACL
2. **hivemq-mqtt-message-log-extension**: audit trail
3. Custom Authorizer extension implementing the per-username rules
   from `acl_hardened_final.conf` (this repo).

The Final-campaign findings on HiveMQ CE were:
- M3 retain poison (default config persists retained msgs)
- M4 wildcard eavesdrop (anonymous '#' subscription)
- C1 will+retain chain (composes M1+M3)
- C2 amplification (HiveMQ correctly de-duplicated to 1 copy)
- M5 ClientID race (HiveMQ aggressively kills victim — already strict)

The extensions plus XML config above neutralize the first three;
C2 was already best-in-class, no additional change needed.
