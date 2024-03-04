import logging

logging.basicConfig(filename='logs/log.log',
                    filemode='a',
                    level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)-8s [%(filename)s:%(lineno)d in %(funcName)s()] %(message)s',
                    datefmt='%m-%d %H:%M:%S')

logger = logging.getLogger(__name__)
