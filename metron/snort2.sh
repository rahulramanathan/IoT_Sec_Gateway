c#!/bin/bash

update_es() {
    curl -XPUT 'http://node1:9200/_template/snort2_index' -d '
{
  "template": "snort2_index*",
  "mappings": {
    "snort2_doc": {
      "dynamic_templates": [
      {
        "geo_location_point": {
          "match": "enrichments:geo:*:location_point",
          "match_mapping_type": "*",
          "mapping": {
            "type": "geo_point"
          }
        }
      },
      {
        "geo_country": {
          "match": "enrichments:geo:*:country",
          "match_mapping_type": "*",
          "mapping": {
            "type": "keyword"
          }
        }
      },
      {
        "geo_city": {
          "match": "enrichments:geo:*:city",
          "match_mapping_type": "*",
          "mapping": {
            "type": "keyword"
          }
        }
      },
      {
        "geo_location_id": {
          "match": "enrichments:geo:*:locID",
          "match_mapping_type": "*",
          "mapping": {
            "type": "keyword"
          }
        }
      },
      {
        "geo_dma_code": {
          "match": "enrichments:geo:*:dmaCode",
          "match_mapping_type": "*",
          "mapping": {
            "type": "keyword"
          }
        }
      },
      {
        "geo_postal_code": {
          "match": "enrichments:geo:*:postalCode",
          "match_mapping_type": "*",
          "mapping": {
            "type": "keyword"
          }
        }
      },
      {
        "geo_latitude": {
          "match": "enrichments:geo:*:latitude",
          "match_mapping_type": "*",
          "mapping": {
            "type": "float"
          }
        }
      },
      {
        "geo_longitude": {
          "match": "enrichments:geo:*:longitude",
          "match_mapping_type": "*",
          "mapping": {
            "type": "float"
          }
        }
      },
      {
        "timestamps": {
          "match": "*:ts",
          "match_mapping_type": "*",
          "mapping": {
            "type": "date",
            "format": "epoch_millis"
          }
        }
      },
      {
        "threat_triage_score": {
          "mapping": {
            "type": "float"
          },
          "match": "threat:triage:*score",
          "match_mapping_type": "*"
        }
      },
      {
        "threat_triage_reason": {
          "mapping": {
            "type": "text",
            "fielddata": "true"
          },
          "match": "threat:triage:rules:*:reason",
          "match_mapping_type": "*"
        }
      },
      {
        "threat_triage_name": {
          "mapping": {
            "type": "text",
            "fielddata": "true"
          },
          "match": "threat:triage:rules:*:name",
          "match_mapping_type": "*"
        }
      }
      ],
      "properties": {
        "timestamp": {
          "type": "date",
          "format": "epoch_millis"
        },
        "source:type": {
          "type": "keyword"
        },
        "ip_dst_addr": {
          "type": "ip"
        },
        "ip_dst_port": {
          "type": "integer"
        },
        "ip_src_addr": {
          "type": "ip"
        },
        "ip_src_port": {
          "type": "integer"
        },
	"dgmlen": {
	  "type": "integer"
	},
	"ethdst": {
	  "type": "keyword"
	},
	"ethlen": {
	  "type": "keyword"
	},
	"ethsrc": {
	  "type": "keyword"
	},
	"id": {
	  "type": "integer"
	},
	"iplen": {
	  "type": "integer"
	},
        "is_alert": {
          "type": "boolean"
        },
      	"msg": {
	  "type": "text",
	  "fielddata": "true"
	},
	"protocol": {
	  "type": "keyword"
	},
	"sig_generator": {
	  "type": "keyword"
	},
	"sig_id": {
	  "type": "integer"
	},
	"sig_rev": {
	  "type": "text",
	  "fielddata": "true"
	},
	"tcpack": {
	  "type": "text",
	  "fielddata": "true"
	},
	"tcpflags" : {
	  "type": "text",
	  "fielddata": "true"
	},
	"tcpseq": {
	  "type": "text",
	  "fielddata": "true"
	},
	"tcpwindow": {
	  "type": "text",
	  "fielddata": "true"
	},
	"tos": {
	  "type": "integer"
	},
	"ttl": {
	  "type": "integer"
	},
        "guid": {
          "type": "keyword"
        },
	"alert": {
	  "type": "nested"
	}
      }
    }
  }
}
'

## List of all properties: https://github.com/apache/metron/blob/master/metron-platform/metron-parsers/src/main/java/org/apache/metron/parsers/snort/BasicSnortParser.java
    
}

# variables
export ZOOKEEPER=node1:2181
export BROKERLIST=node1:6667
export HDP_HOME="/usr/hdp/current"
export METRON_VERSION="0.5.0"
export METRON_HOME="/usr/metron/${METRON_VERSION}"

# Setup new Kafka topic (called snort2)
${HDP_HOME}/kafka-broker/bin/kafka-topics.sh --zookeeper $ZOOKEEPER --create --topic snort2 --partitions 1 --replication-factor 1

# Setup parsing
echo '{
"parserClassName":"org.apache.metron.parsers.snort.BasicSnortParser",
"sensorTopic":"snort2",
"parserConfig": {}
}' | sudo tee ${METRON_HOME}/config/zookeeper/parsers/snort2.json


# Setup indexing
echo '{
"elasticsearch": {
"index": "snort2",
"batchSize": 5,
"enabled" : true
},
"hdfs" : {
"index": "snort2",
"batchSize": 5,
"enabled" : true
}
}' | sudo tee ${METRON_HOME}/config/zookeeper/indexing/snort2.json

# Elasticsearch update
update_es

# Upload configuration to zookeeper
${METRON_HOME}/bin/zk_load_configs.sh -i ${METRON_HOME}/config/zookeeper -m PUSH -z $ZOOKEEPER

# Start new parser
${METRON_HOME}/bin/start_parser_topology.sh -k $BROKERLIST -z $ZOOKEEPER -s snort2
