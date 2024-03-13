#!/bin/bash

compliance_filename="SCC-compliance.json"
filename="rules.txt"
total_lines=$(wc -l < "$filename")
counter=0


  echo '{
    "reports": {
        "scc": {
            "id": "scc",
            "type": "compliance",
            "title": "SCC",
            "conditions": [' > "$compliance_filename"
  while IFS= read -r line; do
          ((counter++))
          if [ $counter -eq $total_lines ]; then
            ID=$(echo "$line" | awk '{print $1}')
            printf '"%s"\n' "$ID" >> "$compliance_filename"
          else
            ID=$(echo "$line" | awk '{print $1}')
            printf '"%s",\n' "$ID" >> "$compliance_filename"
         fi
  done < "$filename"
  echo '
            ]
        }
    },
    "conditions": { ' >> "$compliance_filename"
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
            printf '"%s": { "id": "%s", "name": "%s", "description": "%s", "type": "inventory", "condition_for": "passing", "rules": [ { "attribute": "SCC 5.8 pass", "operator": "matches", "value": "%s" } ], "category": "%s", "severity": "%s", "host_filter": "scc_inventory_enabled" }\n' $ID $ID $ID "$DESCRIPTION" $ID "$CATEGORY" $SEVERITY >> "$compliance_filename"
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
            printf '"%s": { "id": "%s", "name": "%s", "description": "%s", "type": "inventory", "condition_for": "passing", "rules": [ { "attribute": "SCC 5.8 pass", "operator": "matches", "value": "%s" } ], "category": "%s", "severity": "%s", "host_filter": "scc_inventory_enabled" },\n' $ID $ID $ID "$DESCRIPTION" $ID "$CATEGORY" $SEVERITY >> "$compliance_filename"
         fi
  done < "$filename"
  printf '}\n}' >> "$compliance_filename"

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
