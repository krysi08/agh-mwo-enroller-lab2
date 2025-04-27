package com.company.enroller.controllers;


import com.company.enroller.model.Meeting;
import com.company.enroller.model.Participant;
import com.company.enroller.persistence.MeetingService;
import com.company.enroller.persistence.ParticipantService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Collection;

@RestController
@RequestMapping("/meetings")
public class MeetingRestController {

    @Autowired
    MeetingService meetingService;

    @Autowired
    ParticipantService participantService;

    @RequestMapping(value = "", method = RequestMethod.GET)
    public ResponseEntity<?> getMeetings() {
        Collection<Meeting> meetings = meetingService.getAll();
        return new ResponseEntity<Collection<Meeting>>(meetings, HttpStatus.OK);
    }

    @RequestMapping(value = "/{id}", method = RequestMethod.GET)
    public ResponseEntity<?> getMeeting(@PathVariable("id") Long id) {
        Meeting meeting = meetingService.findById(id);
        if (meeting == null) {
            return new ResponseEntity(HttpStatus.NOT_FOUND);
        }
        return new ResponseEntity<Meeting>(meeting, HttpStatus.OK);
    }

    @RequestMapping(value = "", method = RequestMethod.POST)
    public ResponseEntity<?> addMeetings(@RequestBody Meeting meeting) {
        if (meetingService.findById(meeting.getId()) != null) {
            return new ResponseEntity<String>(
                    "Unable to create. A Meeting by Id " + meeting.getId() + " already exist.",
                    HttpStatus.CONFLICT);
        }
        meetingService.add(meeting);
        return new ResponseEntity<Meeting>(meeting, HttpStatus.CREATED);
    }

    @RequestMapping(value = "/{id}", method = RequestMethod.DELETE)
    public ResponseEntity<?> delete(@PathVariable("id") Long id) {
        Meeting meeting = meetingService.findById(id);
        if (meeting == null) {
            return new ResponseEntity(HttpStatus.NOT_FOUND);
        }
        meetingService.delete(meeting);
        return new ResponseEntity<Meeting>(HttpStatus.OK);
    }

    @RequestMapping(value = "/{id}", method = RequestMethod.PUT)
    public ResponseEntity<?> update(@PathVariable("id") Long id, @RequestBody Meeting updatedMeeting) {
        Meeting meeting = meetingService.findById(id);
        if (meeting == null) {
            return new ResponseEntity(HttpStatus.NOT_FOUND);
        }

        return new ResponseEntity<Meeting>(HttpStatus.OK);
    }

    @PostMapping("/{meetingId}/participants/{participantLogin}")
    public ResponseEntity<?> addParticipantToMeeting(@PathVariable("meetingId") Long meetingId,
                                                     @PathVariable("participantLogin") String participantLogin) {
        Meeting meeting = meetingService.findById(meetingId);
        Participant participant = participantService.findByLogin(participantLogin);

        if (meeting == null || participant == null) {
            return ResponseEntity.notFound().build();
        }

        meetingService.addParticipantToMeeting(meeting, participant);
        return ResponseEntity.ok("Participant added to meeting");
    }


    @DeleteMapping("/{meetingId}/participants/{participantLogin}")
    public ResponseEntity<?> removeParticipantFromMeeting(@PathVariable("meetingId") Long meetingId,
                                                          @PathVariable("participantLogin") String participantLogin) {
        Meeting meeting = meetingService.findById(meetingId);
        Participant participant = participantService.findByLogin(participantLogin);

        if (meeting == null || participant == null) {
            return ResponseEntity.notFound().build();
        }

        meetingService.removeParticipantFromMeeting(meeting, participant);
        return ResponseEntity.ok("Participant removed from meeting");
    }


    @GetMapping("/{meetingId}/participants")
    public ResponseEntity<?> getParticipantsOfMeeting(@PathVariable("meetingId") Long meetingId) {
        Meeting meeting = meetingService.findById(meetingId);

        if (meeting == null) {
            return ResponseEntity.notFound().build();
        }

        Collection<Participant> participants = meetingService.getParticipantsForMeeting(meeting);
        return ResponseEntity.ok(participants);
    }

}


