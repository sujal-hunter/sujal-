#!/bin/bash

host=$1

wordlist="/root/tools/SecLists/Discovery/DNS/deepmagic.com-prefixes-top500.txt"

resolvers="/root/basic-recon/resolvers.txt"

resolve_domain="/root/tools/massdns/bin/massdns -r /root/basic-recon/resolved.txt -t A -o -w"


domain_enum(){

    for domain in $(cat $host);

    do

        mkdir -p $domain $domain/sources $domain/Recon $domain/Recon/nuclei $domain/Recon/wayback $domain/Recon/gf $domain/Recon/wordlist $domain/Recon/masscan 

        subfinder -d $domain -o $domain/sources/subfinder.txt

        assetfinder -subs-only $domain | tee $domain/sources/assetfinder.txt

        amass enum -passive -d $domain -o $domain/sources/amass.txt 

        shuffledns -d $domain -w $wordlist -r $resolvers -o $domain/sources/shuffledns.txt 

        cat $domain/sources/*.txt > $domain/sources/all.txt

    done

}

domain_enum

resolving_domains(){

    for domain in $(cat $host);

    do

     shuffledns -d $domain -list $domain/sources/all.txt -o $domain/domains.txt -r $resolvers
     
 done

}
resolving_domains

http_prob(){

    for domain in $(cat $host);

    do

       cat $domain/domains.txt | httpx -threads 200 -o $domain/Recon/httpx.txt
       
   done

}
http_prob

scanner(){

    for domain in $(cat $host);

    do

        cat $domain/Recon/httpx.txt | nuclei -t /root/tools/nuclei-templates/cves/ -c 50 -o $domain/Recon/nuclei/cves.txt

        cat $domain/Recon/httpx.txt | nuclei -t /root/tools/nuclei-templates/vulnerabilities/ -c 50 -o $domain/Recon/nuclei/vulnerabilities.txt

        cat $domain/Recon/httpx.txt | nuclei -t /root/tools/nuclei-templates/dns/ -c 50 -o $domain/Recon/nuclei/dns.txt

        cat $domain/Recon/httpx.txt | nuclei -t /root/tools/nuclei-templates/default-logins/ -c 50 -o $domain/Recon/nuclei/default-logins.txt

        cat $domain/Recon/httpx.txt | nuclei -t /root/tools/nuclei-templates/exposed-panels/ -c 50 -o $domain/Recon/nuclei/exposed-panels.txt

        cat $domain/Recon/httpx.txt | nuclei -t /root/tools/nuclei-templates/exposed-tokens/ -c 50 -o $domain/Recon/nuclei/exposed-tokens.txt

        cat $domain/Recon/httpx.txt | nuclei -t /root/tools/nuclei-templates/fuzzing/ -c 50 -o $domain/Recon/nuclei/fuzzing.txt

        cat $domain/Recon/httpx.txt | nuclei -t /root/tools/nuclei-templates/helpers/ -c 50 -o $domain/Recon/nuclei/helpers.txt

        cat $domain/Recon/httpx.txt | nuclei -t /root/tools/nuclei-templates/iot/ -c 50 -o $domain/Recon/nuclei/iot.txt

        cat $domain/Recon/httpx.txt | nuclei -t /root/tools/nuclei-templates/miscellaneous/ -c 50 -o $domain/Recon/nuclei/miscellaneous.txt

        cat $domain/Recon/httpx.txt | nuclei -t /root/tools/nuclei-templates/misconfiguration/ -c 50 -o $domain/Recon/nuclei/misconfiguration.txt

        cat $domain/Recon/httpx.txt | nuclei -t /root/tools/nuclei-templates/network/ -c 50 -o $domain/Recon/nuclei/network.txt

        cat $domain/Recon/httpx.txt | nuclei -t /root/tools/nuclei-templates/takeovers/ -c 50 -o $domain/Recon/nuclei/takeovers.txt

        cat $domain/Recon/httpx.txt | nuclei -t /root/tools/nuclei-templates/technologies/ -c 50 -o $domain/Recon/nuclei/technologies.txt

        
    done

}

scanner

wayback_data(){

    for domain in $(cat $host);

    do


        cat $domain/domains.txt | waybackurls | tee $domain/Recon/wayback/tmp.txt

        cat $domain/Recon/wayback/tmp.txt | egrep -v "\.woff|\.ttf|\.svg|\.eot|\.png|\.jpep|\.jpg|\.svg|\.css|\.ico" | sed 's/:80//g;s/:443//g' | sort -u >> $domain/Recon/wayback/wayback.txt 

        rm $domain/Recon/wayback/tmp.txt

    done

}

wayback_data

valid_urls(){

    for domain in $(cat $host);

    do


        fuzzer -c -u "FUZZ" -w $domain/Recon/wayback/wayback.txt -of csv  -o $domain/Recon/wayback/valid-tmp.txt

        cat $domain/Recon/wayback/valid-tmp.txt | grep http | awk -F "," '{print $1}' >> $domain/Recon/wayback/valid.txt

        rm $domain/Recon/wayback/valid-tmp.txt


    done

}

valid_urls

gf_patterns(){

    for domain in $(cat $host);

    do

        gf debug_logic $domain/Recon/wayback/valid.txt | tee $domain/Recon/gf/debug_logic.txt

        gf idor $domain/Recon/wayback/valid.txt | tee $domain/Recon/gf/idor.txt

        gf img-trlaversal $domain/Recon/wayback/valid.txt | tee $domain/Recon/gf/img-trlaversal.txt

        gf interestingEXT $domain/Recon/wayback/valid.txt | tee $domain/Recon/gf/interestingEXT.txt   

        gf interestingparams $domain/Recon/wayback/valid.txt | tee $domain/Recon/gf/interestingparams.txt

        gf interestingsubs $domain/Recon/wayback/valid.txt | tee $domain/Recon/gf/interestingsubs.txt

        gf jsvar $domain/Recon/wayback/valid.txt | tee $domain/Recon/gf/jsvar.txt 

        gf lfi $domain/Recon/wayback/valid.txt | tee $domain/Recon/gf/lfi.txt  

        gf rce $domain/Recon/wayback/valid.txt | tee $domain/Recon/gf/rce.txt

        gf redirect $domain/Recon/wayback/valid.txt | tee $domain/Recon/gf/redirect.txt 

        gf sqli $domain/Recon/wayback/valid.txt | tee $domain/Recon/gf/sqli.txt

        gf ssrf $domain/Recon/wayback/valid.txt | tee $domain/Recon/gf/ssrf.txt

        gf xss $domain/Recon/wayback/valid.txt | tee $domain/Recon/gf/xss.txt

    done
    
}

gf_patterns

customize_wordlist(){

    for domain in $(cat $host);

    do
        cat $domain/Recon/wayback/wayback.txt | unfurl -unique paths > $domain/Recon/wordlist/path.txt

        cat $domain/Recon/wayback/wayback.txt | unfurl -unique keys > $domain/Recon/wordlist/params.txt

    done

}

customize_wordlist



subdomain-takeover

get_ip(){

    for domain in $(cat $host);

    do

        $resolve_domain $domain/Recon/masscan/results.txt $domain/domain.txt

        gf ip $domain/Recon/masscan/results.txt | sort -u > $domain/Recon/masscan/ip.txt

    done

}

get_ip

subdomains-takeover(){

    for domain in $(cat $host);

    do

        aquatone-Discovery --domain $domain 

        aquatone-scane --domain $domain

        aquatone-takeover -d $domain

        sudo aquatone-gather -d $domain

    done

}








