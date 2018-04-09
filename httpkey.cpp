#include "widget.h"
#include <QList>
#define STRSIZE 1024
#define BUFSIZE 10240

int HttpKeyData(QByteArray HTTPKey,char *head_str,char *tail_str,char *buf)
{
    int i,j;
    int head_index, tail_index;
    int head_len, tail_len;
    char head_tmp[STRSIZE], tail_tmp[STRSIZE];
    //初始化
    i = 0;
    head_index = 0, tail_index = 0;
    memset(head_tmp, 0, sizeof(head_tmp));
    memset(tail_tmp, 0, sizeof(tail_tmp));
    //memset(buf, 0,sizeof(buf));
    head_len = strlen(head_str);
    tail_len = strlen(tail_str);
    //查找 host_str
    if(HTTPKey.size() < 1)
    {
        sprintf(buf, "can not find %s \r\n", head_str);
        exit(0);
    }
    for(i = 0; i <= (HTTPKey.size() - 1); i++) //逐个字节遍历
    {
        head_tmp[0] = HTTPKey.data()[i];
        if(head_tmp[0] == head_str[0]) //匹配到第一个字符
        {
            for(j=1, i = i+ 1; j<head_len; j++, i++) //匹配 head_str 的其他字符
             {
                 head_tmp[j]=HTTPKey.data()[i];
                 if(head_tmp[j] != head_str[j])
                    break;
             }
            if(j == head_len) //匹配 head_str 成功，停止遍历
            {
                head_index = i;
            }
        }//end if
        tail_tmp[0] = HTTPKey.data()[i];
        if((tail_tmp[0] == tail_str[0])&(head_index > 1)) //匹配到第一个字符
        {
            for(j=1, i = i + 1; j<tail_len; j++, i++) //匹配 tail_str 的其他字符
             {
                 tail_tmp[j]=HTTPKey.data()[i];
                 if(tail_tmp[j] != tail_str[j])
                    break;
             }
            if(j == tail_len) //匹配 head_str 成功，停止遍历
            {
                tail_index = i;
            }
        }//end if
        if(head_index < tail_index)
        {
            for(j = 0; j < (tail_index - head_index); j++)
                buf[j] = HTTPKey.data()[j + head_index];
            return (tail_index - head_index);
        }
    }
    return 0;
    //printf("host_tmp=%s \n", host_tmp);
    //printf("val=%s\n", buf);
}
