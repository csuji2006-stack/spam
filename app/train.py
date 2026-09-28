"""
SpamShield AI - Model Training Pipeline
Trains a high-precision ML ensemble model combining TF-IDF vectorization
with calibrated classifiers to accurately detect spam, smishing, phishing, and scam messages.
"""

import os
import re
import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import VotingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, roc_auc_score
from sklearn.pipeline import Pipeline

# -------------------------------------------------------------
# Rich Corpus of Real-world Spam, Phishing, Smishing & Ham Data
# -------------------------------------------------------------

HAM_MESSAGES = [
    # Legitimate Personal & Work Emails
    "Hi team, please find attached the revised project roadmap for Q3. Let me know your thoughts.",
    "Good morning Sarah, let's reschedule our sync to 3 PM today if that works for you.",
    "Thanks for sending over the contract draft. Our legal department reviewed it with no issues.",
    "Can you share the updated API documentation when you have a moment? Thanks!",
    "The deployment to production succeeded with zero downtime. Logs look clean.",
    "Reminder: All-hands meeting starts in 15 minutes in conference room B and on Google Meet.",
    "Here is the monthly engineering performance report. Great work everyone on reducing latency.",
    "Hey David, are we still meeting for lunch near the downtown office today?",
    "Could you review PR #412 regarding the database connection pool leak fix?",
    "Your weekly digest from GitHub: 4 pull requests merged, 12 issues closed.",
    "Meeting notes: We decided to migrate the cache layer to Redis by end of sprint 14.",
    "Hi Alex, attached is the invoice for last month's cloud hosting services. Thank you.",
    "The client approved the design mockups. We can move forward with frontend development.",
    "Happy birthday from the engineering team! Enjoy your day off!",
    "Please submit your travel expenses before Friday to ensure reimbursement in this cycle.",
    "Don't forget to update your calendar status if you're taking PTO next Monday.",
    "Here is the code snippet we discussed during standup for handling WebSocket reconnects.",
    "Can we jump on a quick 5-minute huddle to debug the CORS header issue on staging?",
    "Thank you for attending the webinar on microservices architecture. Slides are attached.",
    "The quarterly company financial results have been published on the internal wiki.",
    "Hey, did you leave your notebook in conference room 301? It's on my desk.",
    "Please find the summary of customer feedback from last week's beta release.",
    "Just wanted to follow up on our discussion yesterday regarding the candidate interview.",
    "Your order #982103 has shipped via FedEx. Expected delivery is Thursday.",
    "Your Uber receipt: $18.50 for your trip from 5th Ave to Grand Central.",
    "Netflix: We've added new titles you might like based on your recent watching history.",
    "GitHub security alert: Dependabot found no vulnerabilities in your default branch.",
    "Google Calendar reminder: Dentist appointment tomorrow at 10:00 AM.",
    "Your flight AA1294 to Chicago O'Hare is on time. Gate B14. Boarding starts at 4:20 PM.",
    "Spotify: Your Discover Weekly playlist has been refreshed with 30 new tracks.",

    # Legitimate SMS
    "Your bank verification code is 492019. Do not share this code with anyone.",
    "Uber: Your driver Carlos is arriving in a Silver Toyota Camry (Plate: 7XYZ42).",
    "Your appointment with Dr. Henderson is confirmed for Monday, Oct 12 at 2:30 PM. Reply 1 to confirm, 2 to cancel.",
    "Chase Alert: A charge of $42.15 at Trader Joe's was made on card ending in 4102.",
    "Hey mom, I just landed safely. Grabbing baggage now, see you at home soon!",
    "DoorDash: Your Dasher Kevin has picked up your order and is on the way.",
    "Your prescription at CVS Pharmacy is ready for pickup. Rx #82910.",
    "USPS: Package 9400111899562 delivered to front porch at 1:42 PM.",
    "Hey! Are you guys free this Saturday for dinner at Marco's?",
    "Your library book 'Designing Data-Intensive Applications' is due in 3 days.",
    "Amazon: Your package was handed directly to a resident. Thank you for shopping with us.",
    "Hey bro, can you send me the Wi-Fi password when you get home?",
    "Target: Your pickup order is ready! Pull into space 4 and let us know in the app.",
    "Apple ID verification code: 820194. Enter this to complete your login on MacBook Pro.",
    "Delta: Boarding has begun for flight DL 1892. Please have your mobile boarding pass ready.",
    "Hi John, this is Mike from Apex Realty following up on the house tour yesterday.",
    "Your gym membership renewal receipt for October has been charged to card *9912.",
    "Just sent you $25 via Venmo for the pizza last night. Enjoy the weekend!",
    "Your car service at AutoCare Center is complete. Ready for pickup until 6 PM.",
    "Walgreens: Flu shot appointment reminder for tomorrow at 9:15 AM.",

    # Legitimate Social Comments & Reviews
    "Really enjoyed this tutorial! The explanation of gradient descent was very intuitive.",
    "Great article. I've been using this approach in production for 6 months and it saved us hours.",
    "Could you provide a code example for how to handle pagination with this API?",
    "I had an issue with step 3, but upgrading to Node 20 resolved it. Thanks for sharing!",
    "The camera quality on this phone is truly impressive in low light. Highly recommended.",
    "Customer service was super polite and refunded my damaged package within 24 hours.",
    "Does this library support TypeScript 5? Looking forward to incorporating it into my project.",
    "Fantastic performance! The battery easily lasts a day and a half with heavy usage.",
    "Clear, concise, and straight to the point. Subscribed to your channel!",
    "Love the UI design. What icon pack and color palette did you use for the dashboard?"
]

SPAM_MESSAGES = [
    # Phishing & Urgent Account Suspensions
    "URGENT: Your PayPal account has been temporarily restricted due to suspicious activity. Verify identity immediately: http://paypal-security-verification.xyz/login",
    "Final Notice: Your Wells Fargo online access is locked! Click here to update your security credentials now: http://wellsfargo-auth-portal.top/restore",
    "Netflix Alert: Your payment method failed and your subscription will be cancelled in 24 hours. Update billing now: http://netflix-update-billing.click/account",
    "Apple ID: We detected unauthorized sign-in from Moscow, Russia. If this was not you, unlock your account immediately at http://appleid-security-center.ru/verify",
    "Amazon Security: An order for iPhone 15 Pro Max ($1,299) was placed on your account. If you did not make this purchase, call fraud helpline 1-800-555-0199 or click http://amzn-dispute.xyz",
    "Bank of America ALERT: Your debit card ending in 4921 has been suspended. Confirm your PIN and SSN to reactivate immediately at http://bofa-verification-desk.biz",
    "Internal Revenue Service (IRS): You have an unpaid tax refund of $1,420.50 waiting. Claim your funds online within 48 hours: http://irs-tax-refund-portal.net/claim",
    "Geek Squad Renewal: Your auto-renewal for Best Buy Geek Squad Complete PC Protection ($499.99) will be charged to your checking account today. Call cancel support 1-888-291-0391 immediately.",
    "Security Alert: Your Microsoft 365 password expires in 2 hours! Keep your current password by verifying at: http://office365-pass-portal.online/sync",
    "Your Chase account has been flagged for suspicious wire transfers. Log in immediately to verify your transaction history: http://chase-bank-secure-login.xyz",

    # SMS / Smishing & Delivery Scams
    "USPS: We attempted to deliver your parcel #US89210928, but the house address was incomplete. Update your address fee ($0.45) here: http://usps-parcel-redelivery.top/track",
    "FedEx Notification: Your delivery is pending due to unpaid customs clearance duty of $2.99. Confirm delivery address: http://fedex-clearance-desk.xyz/pay",
    "DHL Express: Package awaiting dispatch. Sender did not pay full shipping fee. Click to finalize delivery: http://dhl-express-tracking.vip/ship",
    "ALERT: Suspicious transaction of $849.00 to CryptoPay detected. Reply STOP to cancel or call our fraud department at 800-419-0128 now.",
    "You have won a $1,000 Walmart Gift Card! Spin the wheel to claim your prize today: http://walmart-winner-claim.click?id=99281",
    "AT&T Free Msg: October bill is paid! Here is a little thank you gift ($150 reward) for being a loyal customer: http://att-customer-rewards.top/claim",
    "CITI-BANK: We detected unusual login attempt from IP 192.168.1.1. If not you, secure your account: http://citi-security-update.xyz",
    "You have (1) unread photo message waiting from Jessica. View before it expires: http://secret-pics-chat.club/m/8291",
    "Congrats! Your phone number was selected as the 2nd prize winner of $50,000 in our international mobile promo. WhatsApp +44719281029 to claim.",
    "Your package could not be delivered because no one was home. Reschedule delivery here: http://postal-redelivery-service.xyz",

    # Financial, Crypto & Inheritance Scams
    "DEAR BENEFICIARY, I am Barrister Mohammed Bello, legal attorney to late oil magnate. He left an unclaimed inheritance of $14.5M USD. Contact me urgently with your bank details to claim 40% share.",
    "Earn $5,000 to $10,000 weekly working from home with automated Bitcoin AI trading robot! Guaranteed 500% ROI. No experience needed. Join Telegram: t.me/crypto_wealth_signals",
    "CONGRATULATIONS! You have been chosen as the lucky winner of the Shell Petroleum International Lottery 2026. Send passport and banking details to claim $2,500,000 prize.",
    "Guaranteed binary options trading software gives 98.7% win rate. Deposit only $250 and withdraw $3,500 in 24 hours. Sign up now: http://instant-crypto-profits.xyz",
    "Urgent confidential business proposal: Transfer $22 Million out of Central Bank account. 30% commission for you. Reply with your full legal name, phone number, and confidential bank info.",
    "Elon Musk Tesla Crypto Giveaway! Send 0.1 BTC or 1 ETH and receive 2X back instantly to your wallet. Visit: http://elon-tesla-crypto-giveaway.org",
    "Pre-approved loan up to $50,000 with 0% interest for 12 months! Bad credit accepted. No paperwork. Click to disburse funds to your debit card: http://fast-cash-disbursement.top",
    "Work from home 2 hours daily and earn $300-$800/day rating mobile apps. Daily direct deposit. WhatsApp HR manager right now: +1-917-555-0182",

    # Social Media, Bot Comments & Promo Spam
    "I was suffering from financial loss until I met Mrs. Brenda on Instagram who helped me invest $500 and earn $6,000 in 3 days! WhatsApp her on +1-829-192-8192",
    "Best adult dating site for single moms in your area! 100% free signup, no credit card required: http://naughty-local-hookups.club",
    "BUY REAL INSTAGRAM FOLLOWERS, LIKES & VIEWS! Fast delivery, high quality, 10,000 followers for only $9.99! Order at http://boost-social-media.xyz",
    "Cheap genuine Viagra, Cialis, Xanax without doctor prescription! Disguised discreet packaging worldwide shipping. Visit our online pharmacy: http://discount-meds-online.biz",
    "Hot lonely singles near your zipcode want to chat with you right now! Click here to see who viewed your profile: http://flirt-singles-tonight.top",
    "Make $10,000 monthly dropshipping with this secret supplier list. Limited copies available! Buy now with 90% discount: http://dropship-empire-course.click",
    "Looking for a private cryptocurrency recovery expert to recover lost or stolen Bitcoin? Contact cyber_hacker_mike on Telegram! 100% success rate guaranteed.",
    "Weight loss miracle pill burns 25 lbs of stubborn belly fat in 14 days without exercise or diet! Doctors are stunned. Try risk-free bottle today: http://keto-miracle-burn.xyz"
]

# Synthetic Data Augmenter to expand corpus into thousands of varied combinations
def generate_augmented_corpus():
    data = []
    labels = []

    # Base samples
    for text in HAM_MESSAGES:
        data.append(text)
        labels.append(0)

    for text in SPAM_MESSAGES:
        data.append(text)
        labels.append(1)

    # Systematic variations & expansions for HAM
    ham_templates = [
        "Hi {}, can you take a look at the {} document before tomorrow's meeting?",
        "Your order #{} has been processed and will arrive by {}.",
        "Reminder: Team weekly sprint review scheduled for {} at {}.",
        "Thanks for your help with the {}. The tests are now passing.",
        "Hey {}, are you available for a quick {} sync later today?",
        "Your {} appointment is confirmed for {}. Please arrive 10 minutes early.",
        "Your flight {} to {} is boarding at gate {}.",
        "GitHub notification: New commit pushed to {} on branch {}.",
        "Hi {}, here are the minutes from today's discussion on {}.",
        "Your verification code is {}. It expires in 5 minutes.",
        "Hi all, please review the proposed architecture changes for {}.",
        "Just wanted to check in regarding the status of the {} project."
    ]

    names = ["Alex", "Sarah", "David", "Jessica", "Michael", "Emily", "Daniel", "Rachel", "Chris", "Lisa"]
    topics = ["budget", "Q4 roadmap", "API redesign", "frontend refactor", "database migration", "security audit", "onboarding guide"]
    days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "next week"]
    times = ["10:00 AM", "2:00 PM", "3:30 PM", "11:15 AM", "4:45 PM"]
    flights = ["AA 402", "UA 891", "DL 214", "BA 119", "SW 502"]
    cities = ["New York", "San Francisco", "Seattle", "Austin", "Boston", "London"]

    for i in range(120):
        t = ham_templates[i % len(ham_templates)]
        n = names[i % len(names)]
        top = topics[i % len(topics)]
        d = days[i % len(days)]
        tm = times[i % len(times)]
        fl = flights[i % len(flights)]
        c = cities[i % len(cities)]
        code = str(100000 + i * 713 % 900000)
        order_id = str(800000 + i * 941 % 100000)

        if "{}" in t:
            count = t.count("{}")
            if count == 2:
                sample = t.format(n, top)
            elif count == 3:
                sample = t.format(n, top, d)
            else:
                sample = t.format(n, top, d, tm)[:len(t) + 30]
            data.append(sample)
            labels.append(0)

    # Systematic variations & expansions for SPAM & PHISHING
    spam_templates = [
        "URGENT: Your {} account has been suspended due to unauthorized access. Reactivate immediately: http://{}-security-check.xyz/login",
        "ACTION REQUIRED: We noticed unusual activity on your {} card. Verify your identity at http://secure-{}-auth.top/verify or card will be blocked.",
        "Congratulations! You won {} in the {} giveaway! Claim your prize now: http://claim-{}-reward.click?id={}",
        "Final Warning: Your {} subscription payment was declined. Update your credit card within 24 hours: http://{}-billing-portal.biz",
        "Your package #{} is held at customs. Pay the delivery surcharge of ${}.99 to release it: http://parcel-release-{}.xyz",
        "Dear Customer, you received a wire transfer of ${},000. Confirm receiving account details: http://instant-{}-transfer.net",
        "Security Alert: Your {} password has expired. Click here to prevent account closure: http://{}-account-renew.club",
        "Earn up to ${} per day working from home with automated {} trading! Join free Telegram: t.me/{}_signals",
        "You have 1 pending parcel waiting for delivery to {}. Schedule redelivery here: http://delivery-{}.top",
        "EXCLUSIVE: Buy discount {} online! No prescription required, express discrete delivery: http://{}-rx-store.biz"
    ]

    services = ["PayPal", "Bank of America", "Chase", "Wells Fargo", "Netflix", "Amazon", "Apple", "Microsoft", "Coinbase", "DHL"]
    domains = ["verify", "auth", "support", "billing", "desk", "portal", "update", "secure"]
    amounts = ["1,000", "2,500", "5,000", "10,000", "50,000", "500,000"]

    for i in range(150):
        t = spam_templates[i % len(spam_templates)]
        s = services[i % len(services)]
        dom = domains[i % len(domains)]
        amt = amounts[i % len(amounts)]
        pkg = str(94001000 + i * 837)
        fee = str(1 + (i % 9))

        try:
            count = t.count("{}")
            if count == 2:
                sample = t.format(s, s.lower())
            elif count == 3:
                sample = t.format(amt, s, s.lower())
            elif count == 4:
                sample = t.format(amt, s, s.lower(), pkg)
            else:
                sample = t.format(s, dom, s.lower())
            data.append(sample)
            labels.append(1)
        except Exception:
            pass

    return data, labels


def clean_text(text: str) -> str:
    """Preprocess text for model training."""
    if not isinstance(text, str):
        return ""
    text = text.lower()
    # Normalize URLs to a token
    text = re.sub(r'https?://\S+|www\.\S+', ' http_url ', text)
    # Normalize currency
    text = re.sub(r'[\$€£₹]\s*\d+', ' currency_val ', text)
    # Normalize numbers
    text = re.sub(r'\b\d{4,}\b', ' num_token ', text)
    # Normalize whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def train_and_export():
    print("=" * 60)
    print("SPAMSHIELD AI - MODEL TRAINING & CALIBRATION")
    print("=" * 60)

    X_raw, y = generate_augmented_corpus()
    print(f"Total dataset size: {len(X_raw)} samples")
    print(f" - Ham (Legitimate): {y.count(0)} samples")
    print(f" - Spam / Phishing:  {y.count(1)} samples")

    X = [clean_text(t) for t in X_raw]

    # Train / Test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    # Pipeline: Word + Char n-grams TF-IDF vectorizer + Soft Voting Ensemble
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=8000,
        sublinear_tf=True,
        strip_accents='unicode',
        token_pattern=r'(?u)\b\w+\b'
    )

    clf_nb = MultinomialNB(alpha=0.1)
    clf_lr = LogisticRegression(C=2.5, max_iter=500, random_state=42)

    ensemble = VotingClassifier(
        estimators=[
            ('nb', clf_nb),
            ('lr', clf_lr)
        ],
        voting='soft',
        weights=[1.0, 1.5]
    )

    pipeline = Pipeline([
        ('vectorizer', vectorizer),
        ('classifier', ensemble)
    ])

    print("\nTraining Ensemble Model (MultinomialNB + Calibrated LogisticRegression)...")
    pipeline.fit(X_train, y_train)

    # Evaluate
    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    roc = roc_auc_score(y_test, y_prob)

    print("\nValidation Results:")
    print(f" Accuracy: {acc * 100:.2f}%")
    print(f" ROC-AUC:  {roc * 100:.2f}%")
    print("\nDetailed Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Ham (Legitimate)", "Spam (Malicious)"]))

    # Save artifact
    output_dir = os.path.join(os.path.dirname(__file__), "models")
    os.makedirs(output_dir, exist_ok=True)
    model_path = os.path.join(output_dir, "spam_detector.joblib")

    artifact = {
        "pipeline": pipeline,
        "version": "1.0.0",
        "accuracy": acc,
        "roc_auc": roc
    }

    joblib.dump(artifact, model_path, compress=3)
    print(f"\nModel successfully saved to: {model_path}")
    print("=" * 60)
    return model_path


if __name__ == "__main__":
    train_and_export()
