from ml.preprocessing.email_parser import EmailParser
from ml.features.feature_extractor import EmailFeatureExtractor

def test_feature_extraction():
    parser = EmailParser()
    e1 = parser.parse_raw_text("From: alice@enron.com\nTo: bob@enron.com\nSubject: Project update\n\nMeeting at 2pm.")
    e2 = parser.parse_raw_text("From: eve@suspicious.xyz\nTo: bob@enron.com\nReply-To: evil@darkweb.org\nSubject: URGENT: Account Suspended\n\nClick http://192.168.1.1/login immediately to verify bank details.")

    fe = EmailFeatureExtractor(max_tfidf_features=10)
    fe.fit([e1, e2])
    X = fe.transform([e1, e2])
    assert X.shape[0] == 2
    assert X.shape[1] >= len(fe.tabular_feature_names)
    
    b2 = fe.get_feature_breakdown(e2)
    assert b2["content_heuristics"]["urgent_keywords"] >= 1
    assert b2["routing_headers"]["reply_to_mismatch"] is True
    assert b2["url_analysis"]["has_ip_url"] is True

if __name__ == "__main__":
    test_feature_extraction()
    print("ALL TESTS PASSED")
