# ADD  

### exec_script
```yaml
  - tag: call_route_script
    type: exec_script
    args:
      script_path: /scripts/add_ocserv_route.sh
      dedup_ttl: 300
```
### fakeip_nat
```yaml
  - tag: fakeip_oversea
    type: fakeip_nat
    args:
      table_prefix: "oversea"
      ipv4_range: "198.18.0.0/16"
      next_hop: "10.131.160.3"
      next_hop_dev: "eth0"
```