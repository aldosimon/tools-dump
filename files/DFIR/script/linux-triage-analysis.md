
## auth.log

Failed attempt

```grep Invalid /var/log/auth.log```

```grep "Failed password" /var/log/auth.log | grep "SSH"```


Search IP of invalid login

NF - is used to access the number of fields in the current record. 2 -  Counts from right to left on a specific line. Which is the field for the ip address.

```
awk '/Invalid user/ {print $(NF-2)}' /var/log/auth.log
```

To search for log entries with multiple failed login attempts from the same IP address but different usernames

```awk '/Invalid user/ {print $(NF-2)}' /var/log/auth.log | sort | uniq -c```

## command history

see command history

```cat ~/.bash_history```

see last login

```last -awx```

## check for persistence

### Cron

see cron

```cat /var/log/cron.log```

```crontab -l ```

### services

```service --status-all ```


## References
https://medium.com/@ekeneejike/simple-bash-script-for-log-analysis-db003dd9be
https://medium.com/@DefenderX/incident-response-on-linux-looking-into-right-places-e450db137c23