####################################################################################################
#                                         ssl-check-sjkim.sh                                       #
#                                                                                                  #
#                        This script was created by modified to suit the needs                     #
#         based on the "https://gist.github.com/lkiesow/c9c5d96ecb71822b82cd9d194c581cc8"          #
####################################################################################################

#!/bin/sh
# ssl-check.sh : Check SSL Certificate Expiration Dates

PRINT=true
LOGGER=true
warning_days=60
notice_days=90
[ $# -ge 1 -a -f "$1" ] && input="$1" || input="-"
certs_to_check=$(cat $input)

$PRINT && printf "%4s %26s   %-38s %s\n" "Days" "Expires On" "Domain" "Options"

for CERT in $certs_to_check
do
	add_opts=''
	if [ "$(echo "$CERT" | cut -d: -f2)" -eq 25 ]; then
		add_opts='-starttls smtp'
	fi
	domain="$(echo "$CERT" | cut -d: -f1)"
	output=$(openssl s_client -showcerts -connect "${CERT}" \
		-servername "$domain" $add_opts < /dev/null 2>/dev/null |\
		openssl x509 -noout -dates 2>/dev/null)

	if [ "$?" -ne 0 ]; then
		$PRINT && echo "Error connecting to host for cert [$CERT]"
		$LOGGER && logger -p local6.warn "Error connecting to host for cert [$CERT]"
		continue
	fi

	start_date=$(echo "$output" | grep 'notBefore=' | cut -d= -f2)
	end_date=$(echo "$output" | grep 'notAfter=' | cut -d= -f2)

	start_age=$(date +%s -d "$start_date")
	end_age=$(date +%s -d "$end_date")
	age_now=$(date +%s)

#	end_date=$(date -d "$end_date")

	if [ "$start_age" -gt "$age_now" ]; then
		$PRINT && echo "Certificate for [$CERT] is not yet valid"
		$LOGGER && logger -p local6.warn "Certificate for $CERT is not yet valid"
	fi

	days_to_expire=$(((end_age - age_now) / 86400))

	if [ "$days_to_expire" -lt "$notice_days" ]; then
		$PRINT && echo -en "\033[93m"
		$LOGGER && logger -p local6.warn "cert [$CERT] is soon to expire ($days_to_expire days)"
	fi

	if [ "$days_to_expire" -lt "$warning_days" ]; then
		$PRINT && echo -en "\033[91m"
		$LOGGER && logger -p local6.warn "cert [$CERT] is soon to expire ($days_to_expire days)"
	fi

	$PRINT && printf "%4i %26s   %-38s %s\033[0m\n" "$days_to_expire" "$end_date" "$CERT" "$add_opts"
done

