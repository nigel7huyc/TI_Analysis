FROM python:3.8.11-slim-buster

WORKDIR /root
COPY requirements.txt /tmp/
RUN sed -i 's#deb.debian.org#mirrors.163.com#g' /etc/apt/sources.list \
    && sed -i "s#security.debian.org#mirrors.163.com#g" /etc/apt/sources.list \
    && pip install -U pip -i https://pypi.tuna.tsinghua.edu.cn/simple \
    && pip install --no-cache-dir -r /tmp/requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple \
    && rm -f /tmp/requirements.txt
COPY supervisord.conf /etc/supervisord.conf
ENTRYPOINT ["supervisord","-c", "/etc/supervisord.conf"]
