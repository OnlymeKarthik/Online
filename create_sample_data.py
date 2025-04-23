from app import app, db, User, Election, Candidate
from datetime import datetime, timedelta

def create_sample_data():
    with app.app_context():
        # Create database tables
        db.create_all()
        
        # Create admin user
        admin = User(username='admin', email='admin@example.com', is_admin=True)
        admin.set_password('admin123')
        db.session.add(admin)
        
        # Create sample elections
        elections = [
            {
                'title': 'Student Council President Election 2024',
                'description': 'Vote for your next Student Council President who will lead student initiatives and represent the student body.',
                'candidates': [
                    {'name': 'John Smith', 'description': 'Current Vice President, focusing on mental health awareness and student support programs'},
                    {'name': 'Sarah Johnson', 'description': 'Class Representative, advocating for improved campus facilities and sustainability'},
                    {'name': 'Michael Brown', 'description': 'Student Activist, promoting diversity and inclusion in campus activities'}
                ]
            },
            {
                'title': 'Campus Sustainability Initiative 2024',
                'description': 'Choose the primary environmental project to be implemented on campus this year.',
                'candidates': [
                    {'name': 'Solar Panel Installation', 'description': 'Install solar panels across campus buildings to reduce energy consumption'},
                    {'name': 'Zero-Waste Program', 'description': 'Implement comprehensive recycling and composting systems'},
                    {'name': 'Green Transportation', 'description': 'Introduce electric shuttle buses and expand bike-sharing program'}
                ]
            },
            {
                'title': 'Library Hours Extension Proposal',
                'description': 'Vote on the proposed extension of library operating hours during exam periods.',
                'candidates': [
                    {'name': '24/7 Access', 'description': 'Keep the library open 24/7 during exam weeks'},
                    {'name': 'Extended Hours (6AM-2AM)', 'description': 'Extend current hours from 6AM to 2AM'},
                    {'name': 'Current Hours + Weekend Extension', 'description': 'Keep current weekday hours but extend weekend hours'}
                ]
            },
            {
                'title': 'Campus Food Court Renovation',
                'description': 'Select the preferred renovation plan for the main campus food court.',
                'candidates': [
                    {'name': 'Modern Food Hall', 'description': 'Open concept with multiple international cuisine stations'},
                    {'name': 'Traditional Cafeteria Upgrade', 'description': 'Renovate existing layout with improved facilities'},
                    {'name': 'Hybrid Model', 'description': 'Mix of food court and casual dining spaces'}
                ]
            },
            {
                'title': 'Student Technology Fund Allocation',
                'description': 'Decide how to allocate the student technology fund for the upcoming academic year.',
                'candidates': [
                    {'name': 'Computer Lab Upgrades', 'description': 'New computers and software for all campus labs'},
                    {'name': 'Laptop Lending Program', 'description': 'Expand the laptop lending program for students'},
                    {'name': 'Innovation Hub', 'description': 'Create a new technology innovation space with 3D printers and VR equipment'}
                ]
            }
        ]
        
        # Add elections to database
        for election_data in elections:
            election = Election(
                title=election_data['title'],
                description=election_data['description'],
                start_date=datetime.utcnow(),
                end_date=datetime.utcnow() + timedelta(days=7),
                is_active=True
            )
            db.session.add(election)
            
            for candidate_data in election_data['candidates']:
                candidate = Candidate(
                    name=candidate_data['name'],
                    description=candidate_data['description'],
                    election=election
                )
                db.session.add(candidate)
        
        # Commit all changes
        db.session.commit()
        print("Sample data created successfully!")

if __name__ == '__main__':
    create_sample_data() 