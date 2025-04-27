package com.company.enroller.persistence;

import com.company.enroller.model.Meeting;
import com.company.enroller.model.Participant;
import org.hibernate.Session;
import org.hibernate.Transaction;
import org.hibernate.query.Query;
import org.springframework.stereotype.Component;

import java.util.Collection;

@Component("meetingService")
public class MeetingService {

	Session session;

	public MeetingService() {
		session = DatabaseConnector.getInstance().getSession();
	}

	public Collection<Meeting> getAll() {
		String hql = "FROM Meeting";
		Query query = this.session.createQuery(hql);
		return query.list();
	}

	public Meeting findById(Long id) {
		return session.getSession().get(Meeting.class, id);
	}

	public Meeting add(Meeting meeting) {
		Transaction transaction = session.getSession().beginTransaction();
		session.getSession().save(meeting);
		transaction.commit();
		return meeting;
	}
	public void update(Meeting meeting) {
		Transaction transaction = session.getSession().beginTransaction();
		session.getSession().merge(meeting);
		transaction.commit();
	}

	public void delete(Meeting meeting) {
		Transaction transaction = session.getSession().beginTransaction();
		session.getSession().delete(meeting);
		transaction.commit();
	}

	public void addParticipantToMeeting(Meeting meeting, Participant participant) {
		meeting.addParticipant(participant);
		update(meeting);
	}

	public void removeParticipantFromMeeting(Meeting meeting, Participant participant) {
		meeting.removeParticipant(participant);
		update(meeting);
	}

	public Collection<Participant> getParticipantsForMeeting(Meeting meeting) {
		return meeting.getParticipants();
	}

}
