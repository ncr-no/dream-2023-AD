FROM wert310/gameserver-basechecker:ef3af01

RUN mkdir -p /checker
WORKDIR /checker

#COPY requirements.txt /checker/requirements.txt
#RUN pip install -r requirements.txt

COPY checker.py /checker/checker.py
#COPY dejavu.ttf /checker/dejavu.ttf
USER ctf-checkermaster
ENV CTF_CHECKERSCRIPT /checker/checker.py

# set this to <yourchallengename>_checker<X>
ENV CTF_SERVICE dewaste_checker1

WORKDIR /tmp
