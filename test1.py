'''import datetime
d1 = datetime.datetime(2023, 12,15)
d2 = datetime.datetime(2023,12,2)
d3 = datetime.datetime(2023,12,12)
#print(d1<d2<d3)
#print(d2<d1<d3)   

if d2<d1<d3:
    print("yes")
else:
    print("no")'''

from datetime import datetime

# get current datetime
dt = datetime.now()
print('Datetime is:', dt)

# get weekday name
#print('day Name:', dt.strftime('%A'))
dy=dt.strftime('%A')
print(dy)
