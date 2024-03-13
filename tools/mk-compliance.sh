#!/bin/bash

filename="/root/cfbs/rules.txt"
total_lines=$(wc -l < "$filename")
counter=0


  echo '{
    "reports": {
        "scc": {
            "id": "scc",
            "type": "compliance",
            "title": "SCC",
            "conditions": [' > /tmp/compliance.json
  while IFS= read -r line; do
          ((counter++))
          if [ $counter -eq $total_lines ]; then
            ID=$(echo "$line" | awk '{print $1}')
            printf '"%s"\n' "$ID" >> /tmp/compliance.json
          else
            ID=$(echo "$line" | awk '{print $1}')
            printf '"%s",\n' "$ID" >> /tmp/compliance.json
         fi
  done < "$filename"
  echo '
            ]
        }
    },
    "conditions": { ' >> /tmp/compliance.json
  counter=0
  while IFS= read -r line; do
          ((counter++))
          if [ $counter -eq $total_lines ]; then
            ID=$(echo "$line" | awk '{print $1}')
            DESCRIPTION=$(echo "$line" | cut -d ' ' -f4- | sed 's|/|\/|g')
            DESCRIPTION=$(echo "$DESCRIPTION" | sed "s|\"|'|g")
            CATEGORY=$(echo "$line" | cut -d ' ' -f2-3)
            case $CATEGORY in
              "CAT I")
                SEVERITY="low";;
              "CAT II")
                SEVERITY="medium";;
              "CAT III")
                SEVERITY="high";;
            esac
            printf '"%s": { "id": "%s", "name": "%s", "description": "%s", "type": "inventory", "condition_for": "passing", "rules": [ { "attribute": "SCC 5.8 pass", "operator": "matches", "value": "%s" } ], "category": "%s", "severity": "%s", "host_filter": null }\n' $ID $ID $ID "$DESCRIPTION" $ID "$CATEGORY" $SEVERITY >> /tmp/compliance.json
          else
            ID=$(echo "$line" | awk '{print $1}')
            DESCRIPTION=$(echo "$line" | cut -d ' ' -f4- | sed 's|/|\/|g')
            DESCRIPTION=$(echo "$DESCRIPTION" | sed "s|\"|'|g")
            CATEGORY=$(echo "$line" | cut -d ' ' -f2-3)
            case $CATEGORY in
              "CAT I")
                SEVERITY="low";;
              "CAT II")
                SEVERITY="medium";;
              "CAT III")
                SEVERITY="high";;
            esac
            printf '"%s": { "id": "%s", "name": "%s", "description": "%s", "type": "inventory", "condition_for": "passing", "rules": [ { "attribute": "SCC 5.8 pass", "operator": "matches", "value": "%s" } ], "category": "%s", "severity": "%s", "host_filter": null },\n' $ID $ID $ID "$DESCRIPTION" $ID "$CATEGORY" $SEVERITY >> /tmp/compliance.json
         fi
  done < "$filename"
  printf '}\n}' >> /tmp/compliance.json

#        "v-230520": {
#            "id": "v-230520",
#            "name": "V-230520",
#            "description": "RHEL 8 must mount \/var\/tmp with the nodev option.",
#            "type": "inventory",
#            "condition_for": "passing",
#            "rules": [
#                {
#                    "attribute": "SCC 5.8 pass",
#                    "operator": "matches",
#                    "value": "V-230520"
#                }
#            ],
#            "category": "Cat II",
#            "severity": "medium",
#            "host_filter": null
#        }
#    }
#
