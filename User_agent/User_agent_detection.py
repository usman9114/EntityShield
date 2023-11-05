from crawlerdetect import CrawlerDetect
from user_agents import parse
# true if crawler user agent detected

def detect_single(user_agent):
    try:
        crawler_detect = CrawlerDetect(user_agent=user_agent)
        u_agent = parse(user_agent)
        model = u_agent.device.model

        if 'torrent' in user_agent:
            return {'is_crawler':True, 'is_match': user_agent,'model':model}
        return {'is_crawler':crawler_detect.isCrawler(), 'is_match': crawler_detect.getMatches(), 'model':model}
    except:
        return "Something went wrong, Please check logs"

# Lets analyze user agents

def analyze_user_agents_detect(user_agent_list):
    user_agent_type = {}
    user_agent_type_overall = {}
    user_agent_list = user_agent_list.split(',')
    for i in user_agent_list:
        crawler_detect = CrawlerDetect(user_agent=str(i))
        # Update status code analysis variable
        if crawler_detect.isCrawler():
            detect_type = crawler_detect.getMatches()
            if detect_type not in user_agent_type.keys():
                user_agent_type[detect_type] =  1
            else:
                user_agent_type[detect_type] += 1

            # Update overall user agent count
            if detect_type not in user_agent_type_overall.keys():
                user_agent_type_overall[detect_type] = 1
            else:
                user_agent_type_overall[detect_type] += 1
    return dict(sorted(user_agent_type.items(), key=lambda x: x[1], reverse=True))
