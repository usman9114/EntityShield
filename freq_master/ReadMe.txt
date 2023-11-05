Freq.py is a flask api with two endpoints
1. measure
2. update

-Endpoint Measure: measures randomness/entropy in dns: returns safe/unsafe.
	/measure endpoint expects json format input with post request method, a sample file is placed in data/input folder

-Endpoint Update: is used to manually update weight of dns seen as normal in environment but classified unsafe by model
	expects argument in url /update?dns=fbi
