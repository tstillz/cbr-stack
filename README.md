# Carbon Black Response: CBR Stacking
This script is designed to enable stacking and sub stacking using the CBR API's.
Stacking and sub stacking allows threat hunters to view the CBR data set from multiple angles to identify anomalies. 

This script is related to the blog post: https://blog.stillztech.com/2018/10/smashing-stack-with-carbon-black.html

## Usage
Update the config.json with your Carbon Black URL and API token.
Next, update the `queries` section of the json file with the queries you'd like to test. 
Finally, specify the `year`, `month` and `day` you wish the start stacking. 

Install Python requests
> pip3 install requests 

Running the script
> python3 main.py

