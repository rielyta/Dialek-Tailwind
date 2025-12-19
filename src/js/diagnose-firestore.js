

async function diagnoseUserData() {
    try {
        const user = auth.currentUser;
        if (!user) {
            console.log('❌ Tidak ada user yang login');
            return;
        }

        console.log('👤 Current UID:', user.uid);
        console.log('📧 Email:', user.email);

        // Ambil user doc
        const userRef = firebase.firestore().collection('users').doc(user.uid);
        const userSnap = await userRef.get();

        if (userSnap.exists()) {
            console.log('✅ User document EXISTS');
            console.log('📦 Data:', userSnap.data());
            console.log('📋 Fields:', Object.keys(userSnap.data()));

            const data = userSnap.data();
            
            // Check specific fields
            console.log('--- FIELD CHECK ---');
            console.log('username:', data.username ? '✅' : '❌ MISSING');
            console.log('email:', data.email ? '✅' : '❌ MISSING');
            console.log('name:', data.name ? '✅' : '❌ MISSING');
            console.log('profile_image:', data.profile_image ? '✅' : '❌ MISSING');

            // Suggest fix jika ada yang missing
            if (!data.username) {
                console.warn('⚠️ USERNAME MISSING! Suggesting fix...');
                return suggestFix(user, data);
            }
        } else {
            console.log('❌ User document DOES NOT EXIST!');
            console.log('💡 User might not be initialized after signup');
            return suggestFix(user, {});
        }

    } catch (error) {
        console.error('❌ Error:', error);
    }
}

async function suggestFix(user, userData) {
    console.log('');
    console.log('=== SUGGESTED FIX ===');
    console.log('Run this to fix:');
    console.log('');
    
    const fixCode = `
firebase.firestore().collection('users').doc('${user.uid}').set({
    username: '${user.displayName || 'User' + user.uid.substring(0, 5)}',
    email: '${user.email}',
    profile_image: '${user.photoURL || ''}',
    created_at: new Date().toISOString(),
    ...existingData // ini akan merge dengan data existing
}, { merge: true });
    `;
    
    console.log(fixCode);
}

// Panggil function
diagnoseUserData();


// ==========================================
// OPTION 2: AUTOMATIC FIX FUNCTION
// ==========================================

// Jalankan ini jika diagnosis menemukan masalah:

async function fixMissingUsername() {
    try {
        const user = auth.currentUser;
        if (!user) {
            alert('❌ Login dulu!');
            return;
        }

        const userRef = firebase.firestore().collection('users').doc(user.uid);
        
        await userRef.set({
            username: user.displayName || 'User',
            email: user.email,
            profile_image: user.photoURL || null,
            updated_at: new Date().toISOString()
        }, { merge: true });

        console.log('✅ Username fixed!');
        location.reload();

    } catch (error) {
        console.error('❌ Fix failed:', error);
    }
}

// fixMissingUsername();


// ==========================================
// OPTION 3: CHECK ALL FORUM DATA
// ==========================================

async function diagnoseForum() {
    try {
        console.log('📚 Checking forum_questions...');
        
        const q = firebase.firestore()
            .collection('forum_questions')
            .limit(3);
        
        const snapshot = await q.get();
        
        console.log(`Found ${snapshot.size} questions`);
        
        snapshot.forEach(doc => {
            const data = doc.data();
            console.log('---');
            console.log('ID:', doc.id);
            console.log('Data:', data);
            console.log('Username:', data.username ? '✅' : '❌');
            console.log('UserId:', data.userId ? '✅' : '❌');
        });

    } catch (error) {
        console.error('❌ Error:', error);
    }
}

// diagnoseForum();