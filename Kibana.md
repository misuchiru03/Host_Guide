# Kibana  
---
## <u> Terminology </u>  
| Description | Example |  
|---|---|
| Term = A single word, subset of value| "term"|  
| Phrase = A group of words inside quotes, subset of value | "this is a phrase" |
| Field = Is the name of the field that contains values. Appending a colon tells Lucene this is a Field | @meta.host|
| Value = A value you wish to search | "this is a value or phrase"

## <u> Elastic Special Characters </u>
| Description | Example |  
|---|---|
| Reserved characters, these characters need to be escaped | + - = && > < ! () {} [] \| ^ " ~ * ? : \ / |  
| Break character | \ |  

## <u> Operators </u>  
| Syntax | Description | Example |  
|---|---|---|
| And or && | Only result thaat include both X and Y | http AND www.google.com |  
| OR or \|\| | Only results that include either X or Y | http OR dns |  
| NOT or ! | Only results that do NOT include X | NOT ssl | 
| TO | Results from value X too value Y | [10 to 100] | 
| + | must be present in document text | +www.google.com | 
| - | must not be present in document text | -www.google.com | 
| () | Grouping of values, typically used to apply more advanced Boolean logic | http AND (get or post) | 
| [] | Inclusive range search, typically a number field but can earch tet. Will include specified values | @meta.resp_[1 TO 1024] |  
| {} | Exclusive range search, typiically a number field but can search text. Will exclude specified values | @meta.resp_port{0 TO 1025} |
| \_exists\_ | special operatoro that allows finding documents containing a specified field | \_exists\_:hhtp.host |
| NOT\_exists\_ | By combining the NOT operatoor you can find documents that are missing a field | NOT\_exists\_:http.user\_agent |  

## <u> Term Modifiers </u> 
| Syntax | Description | Example |
|---|---|---|
| ? | Single character wildcard | www.googl?.com |  
| \* | Multiple character wildcard | www.goo*.com |
| ~ | Fuzzy search based on Levens-htein distance | www.google.com~ |  
| ~0.9 | Change weight of fuzzy search, 0 to 1, default 0.5, higher number = higher similarity | www.google.com~0.9 |  
| ~2 | Prozimity search of values within # of each other | "program DOS"~10 |  
| ^ | Boost term to obe more relevant in searches default: 1, Must be Positive, can be decimal | "-lin-ux"^3 |  

## <u> Ranges </u>  
| Description | Example |
|---|---|  
| 1 to 10, including 1 and 10 | [1 TO 10] |  
| 1 to 10, excluding 1 and 10 | {1 TO 10} |  
| 1 to 10 , including 1, excluding 10 | [1 to5} |  
| All days in 2017 | [2017--01--01 TO 2017-1-2-31] |  
| Specific timestamp\* | [2017--01--01T-09:-00:00 TO 2017-0-1-0-1T0-9:0-0:10 |  
| Larger than 10 | >10 |  
| Smaller then 10 | <10 | 
| Larger or equal to 10 | >=10 |  
| Smaller or equal to 10 | <=10 |  

## <u> Field Searching </u>  
| Syntax | Description | Example |
|---|---|---|
| Field:-value | The colon states thhe previus text is a field and the text after it is the value you want to find | http.host:www.google.com |  
| Fiel\?-:value | Wildcards be used inside a field name but need to be escaped | http.\*:www.google.com |  

## <u> Lucene REGEX </u>
| Syntax | Description | Example |
|---|---|---|
| // | All regex starts and ends with a forward slash | /REGEX HERE/ |  
| - | Range operator, a througgh z, - through 9 | /[A-Z]/   (Matches Any single uppercase letter) |
| . | Match any single character | /positv./     (Matches positiv ending in anything) |  
| ? | Preceding value is optional | /joh?n    (Matches john or jon) |  
| + | Preceding value matched one or more times | /go+gle/     (Matches gogle with the o possibly repeating indefinitely) |  
| \* | Preceding value matches zero or more times | /z*/     (Matches nothing or z possibly repeating indefinitely |  
| \| | Alteration operator, typically referred to as OR | /text\|sms/    (Matches text or sms) | 
| [] | List, Matches one of the given expressions inside | /[abc123]/    (Matches a or b or c or 1 or 2 or 3) |  
| () | Grouping, groups expressions together | /(([ab]) or [12])/     (Matches a1 or a2 or b1 or b2) |  
| {} | Intervals, repeat the preceding expression | /[ab]{-1,3}/     (Matches ab or abab or ababab) |  
| \\ | Escape character | /[a\\-z]/      (Matches a or - or z) |  
| " | Only needs escaped because its java regex ||  

## <u> Analyzed vs Not Analyzed (.raw) </u>  
| Description | Example |  
|---|---|
| String (Not Analyzed), fields need to be searched as one phrase. | "Set the shape to semi-transparent by calling set\_trans(5)" |  
| Standard Analyzed, fields can be searched using one or more of its sections | set, the, shape, to, semi, transp-arent, by, calling, set\_trans, 5 |  
| Above is how Elasti00csearch stores analyzed vs not analyzed strings for searching. ||  

## <u> Searching Examples </u>  
| Search Type | Example 1 | Example 2 |  
|---|---|---|  
|Keyword | usbstor | keyword
| OR Keyword | usbstor OR devie-classes | usbstor device-classes |  
| AND Keyword | usbstor AND device-classes ||  
| NOT Keyword | NOT usbstor | NOT device-classes |  
| Pattern | *ywo* | ?eywor? |  
| Phrase* | "/etc/elasticsearch/" ||  
| Phrase* | "/WINDOWS/system32/config/" | "WINDOWS system32 config" |  
| Field Match | termname:keywordone | source\_short:reg source\_short:evt |  
| Field Match | field:term ||  
| Exact Field Match** | field.raw:TeRm ||  
| Exact Field Match** | parser.raw:"sqlite/firefox_cookies" ||  
| Field contains term1 or term2 | fieldd:(term1 or term2) ||  
| OR Term Search | source_short:(reg evt) | source\_short:reg source\_short:evt |  
| Field Exists | \_exists\_:field ||  
| Field Exists | \_exists\_:star ||  
| Field Missing | !(\_exosts\_:field) ||  
| Field Missing | \_missing\_:star ||
| Wildcards*** | *.exe | *.ppt? |
| Regular Expressions | /h?[tx]ml?/ ||  
| Regular Expressions | /doc([mx]?)/ | name:/joh?n(ath[oa]n)/ |  
| Fuzzy | svchost~ | lsass~1 |  
| JSON | {"match":{"field":"term"}} ||  
---
##<u> Common Queries </u>
---
