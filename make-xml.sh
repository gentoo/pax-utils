

echo "<table>"

# we dont use the -v flag yet
newline=0
scanelf | grep -e ^'  -' -e ^$ | while read line; do
	[[ $line == "" ]] && export newline=$((${newline} + 1))
	[[ $newline -le 1 ]] && continue
	[[ $line == "" ]] && echo -e '<tr>\n  <th>Option</th>\n  <th>Long Option</th>\n  <th>Description</th>\n</tr>'
	[[ $line == "" ]] && continue

	echo "<tr>"

	arg=$(echo "${line}" | grep '<arg>' | awk '{print $3}' )
	arg=$(echo $arg | tr '<,>' '[,]')
	[[ $arg != "" ]] && arg=" $arg"

	short_opt=$(echo "${line}" | awk '{print $1}' | sed s/,//)
	printf "%s\n" "${short_opt}${arg}" | awk '{print "  <ti>"$0"</ti>"}'

	long_opt=$(echo "${line}" | awk '{print $2}' )
	printf "%s" "${long_opt}${arg}" | awk '{print "  <ti>"$0"</ti>"}'


	echo "  <ti>$(echo "${line}" | cut -d '*' -f 2- | cut -c 2-)</ti>"
	echo "</tr>"
done
echo "</table>"

exit 0

